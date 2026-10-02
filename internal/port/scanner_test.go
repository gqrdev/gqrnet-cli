package port

import (
	"context"
	"errors"
	"net"
	"strconv"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/gqrdev/gqrnet-cli/internal/network"
)

func TestScanReportsOpenAndClosedPorts(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	openPort := listener.Addr().(*net.TCPAddr).Port

	closedListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	closedPort := closedListener.Addr().(*net.TCPAddr).Port
	if err := closedListener.Close(); err != nil {
		t.Fatal(err)
	}

	result := scan(context.Background(), "example.test", []int{openPort, closedPort}, time.Second, time.Second,
		func(context.Context, string) network.Result { return network.Result{IPv4: []string{"127.0.0.1"}} },
		&net.Dialer{},
	)
	if result.Error != "" {
		t.Fatalf("unexpected scan error: %s", result.Error)
	}
	if len(result.Results) != 2 {
		t.Fatalf("got %d results, want 2", len(result.Results))
	}
	if result.Results[0].Status != StateOpen {
		t.Errorf("open port status = %q, want %q", result.Results[0].Status, StateOpen)
	}
	if result.Results[1].Status != StateClosed {
		t.Errorf("closed port status = %q, want %q", result.Results[1].Status, StateClosed)
	}
	if result.Summary.Open != 1 || result.Summary.Closed != 1 {
		t.Errorf("summary = %#v, want one open and one closed", result.Summary)
	}
	if !result.Complete {
		t.Error("scan should be complete when every attempt returned a conclusive result")
	}
}

type fullScanDialer struct {
	calls atomic.Int32
}

func (dialer *fullScanDialer) DialContext(_ context.Context, _, address string) (net.Conn, error) {
	dialer.calls.Add(1)
	_, portString, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	port, err := strconv.Atoi(portString)
	if err != nil {
		return nil, err
	}
	if port != 443 {
		return nil, syscall.ECONNREFUSED
	}
	connection, peer := net.Pipe()
	_ = peer.Close()
	return connection, nil
}

func TestScanDefaultsToFullRangeAndRetainsOnlyOpenPorts(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	dialer := &fullScanDialer{}
	result := scan(ctx, "example.test", nil, 5*time.Second, time.Second,
		func(context.Context, string) network.Result { return network.Result{IPv4: []string{"127.0.0.1"}} },
		dialer,
	)

	if !result.FullScan || !result.Complete {
		t.Errorf("full_scan=%v complete=%v, want true/true", result.FullScan, result.Complete)
	}
	if len(result.Results) != 1 || result.Results[0].Port != 443 || result.Results[0].Status != StateOpen {
		t.Errorf("results = %#v, want only open port 443", result.Results)
	}
	if got := dialer.calls.Load(); got != maxTCPPort {
		t.Errorf("dial attempts = %d, want %d", got, maxTCPPort)
	}
	if result.Summary.PortsPerAddress != maxTCPPort || result.Summary.Open != 1 || result.Summary.Closed != maxTCPPort-1 || result.Summary.NotChecked != 0 {
		t.Errorf("summary = %#v, want full-range counts", result.Summary)
	}
}

func TestScanRecordsResolutionError(t *testing.T) {
	result := scan(context.Background(), "example.test", []int{443}, time.Second, time.Second,
		func(context.Context, string) network.Result { return network.Result{Error: "lookup failed"} },
		&net.Dialer{},
	)
	if result.Error != "lookup failed" {
		t.Fatalf("error = %q, want lookup failed", result.Error)
	}
	if len(result.Results) != 0 {
		t.Fatalf("got results after resolution error: %#v", result.Results)
	}
}

type blockingDialer struct {
	active  atomic.Int32
	maximum atomic.Int32
}

type deadlineRecordingDialer struct {
	connectionDeadline time.Time
}

func (dialer *deadlineRecordingDialer) DialContext(ctx context.Context, _, _ string) (net.Conn, error) {
	dialer.connectionDeadline, _ = ctx.Deadline()
	<-ctx.Done()
	return nil, ctx.Err()
}

func TestScanAppliesPerConnectionTimeout(t *testing.T) {
	globalDeadline := time.Now().Add(time.Second)
	ctx, cancel := context.WithDeadline(context.Background(), globalDeadline)
	defer cancel()
	dialer := &deadlineRecordingDialer{}
	result := scan(ctx, "example.test", []int{1000}, time.Second, 20*time.Millisecond,
		func(context.Context, string) network.Result { return network.Result{IPv4: []string{"127.0.0.1"}} },
		dialer,
	)

	if !dialer.connectionDeadline.Before(globalDeadline) {
		t.Errorf("connection deadline = %v, global deadline = %v; want connection deadline first", dialer.connectionDeadline, globalDeadline)
	}
	if len(result.Results) != 1 || result.Results[0].Status != StateTimeout {
		t.Errorf("results = %#v, want one timeout result", result.Results)
	}
	if result.Complete {
		t.Error("scan with a connection timeout must be incomplete")
	}
}

func (dialer *blockingDialer) DialContext(ctx context.Context, _, _ string) (net.Conn, error) {
	active := dialer.active.Add(1)
	for maximum := dialer.maximum.Load(); active > maximum; maximum = dialer.maximum.Load() {
		if dialer.maximum.CompareAndSwap(maximum, active) {
			break
		}
	}
	defer dialer.active.Add(-1)
	<-ctx.Done()
	return nil, ctx.Err()
}

func TestScanBoundsConcurrencyAndMarksUnstartedChecks(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	dialer := &blockingDialer{}
	ports := make([]int, 200)
	for index := range ports {
		ports[index] = 1000 + index
	}
	result := scan(ctx, "example.test", ports, 50*time.Millisecond, time.Second,
		func(context.Context, string) network.Result { return network.Result{IPv4: []string{"127.0.0.1"}} },
		dialer,
	)
	if got := dialer.maximum.Load(); got > maxConcurrentChecks {
		t.Errorf("maximum concurrency = %d, want at most %d", got, maxConcurrentChecks)
	}
	if result.Summary.Timeout == 0 || result.Summary.NotChecked == 0 {
		t.Errorf("summary = %#v, want timed out and unstarted checks", result.Summary)
	}
	if result.Summary.Timeout+result.Summary.NotChecked != len(ports) {
		t.Errorf("summary = %#v, want every check timed out or unstarted", result.Summary)
	}
	if result.Complete {
		t.Error("timed out scan must be marked incomplete")
	}
}

func TestClassifyErrorDoesNotTreatTimeoutAsClosed(t *testing.T) {
	if got := classifyError(context.Background(), syscall.ECONNREFUSED); got != StateClosed {
		t.Errorf("refused status = %q, want %q", got, StateClosed)
	}
	if got := classifyError(context.Background(), context.DeadlineExceeded); got != StateTimeout {
		t.Errorf("deadline status = %q, want %q", got, StateTimeout)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if got := classifyError(ctx, context.Canceled); got != StateCancelled {
		t.Errorf("canceled status = %q, want %q", got, StateCancelled)
	}
	if got := classifyError(context.Background(), errors.New("unexpected failure")); got != StateError {
		t.Errorf("unexpected status = %q, want %q", got, StateError)
	}
}
