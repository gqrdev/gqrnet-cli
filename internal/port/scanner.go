package port

import (
	"context"
	"errors"
	"net"
	"sort"
	"strconv"
	"sync"
	"syscall"
	"time"

	"github.com/gqrdev/gqrnet-cli/internal/network"
)

const (
	maxConcurrentChecks = 100
	maxTCPPort          = 65535
)

var serviceHints = map[int]string{
	22:   "ssh",
	25:   "smtp",
	53:   "domain",
	80:   "http",
	110:  "pop3",
	143:  "imap",
	443:  "https",
	587:  "submission",
	993:  "imaps",
	995:  "pop3s",
	1433: "ms-sql-s",
	3306: "mysql",
	5432: "postgresql",
	6379: "redis",
	8080: "http-alt",
	8443: "https-alt",
}

type resolver func(context.Context, string) network.Result

type contextDialer interface {
	DialContext(context.Context, string, string) (net.Conn, error)
}

type checkJob struct {
	address     Address
	port        int
	resultIndex int
}

type checkOutcome struct {
	result      PortResult
	resultIndex int
}

// Scan resolves target and checks each requested TCP port on every resolved IP.
func Scan(ctx context.Context, target string, ports []int, timeout, connectTimeout time.Duration) Result {
	return scan(ctx, target, ports, timeout, connectTimeout, network.ResolveIPs, &net.Dialer{})
}

func scan(ctx context.Context, target string, ports []int, timeout, connectTimeout time.Duration, resolve resolver, dialer contextDialer) Result {
	started := time.Now()
	fullScan := len(ports) == 0
	portCount := len(ports)
	if fullScan {
		portCount = maxTCPPort
	}
	result := Result{
		Target:         target,
		Protocol:       "tcp",
		StartedAt:      started,
		TimeoutMS:      timeout.Milliseconds(),
		FullScan:       fullScan,
		RequestedPorts: append([]int(nil), ports...),
	}

	resolved := resolve(ctx, target)
	if resolved.Error != "" {
		result.Error = resolved.Error
		result.DurationMS = time.Since(started).Milliseconds()
		return result
	}
	addresses := make([]Address, 0, len(resolved.IPv4)+len(resolved.IPv6))
	for _, ip := range resolved.IPv4 {
		addresses = append(addresses, Address{IP: ip, Family: "ipv4"})
	}
	for _, ip := range resolved.IPv6 {
		addresses = append(addresses, Address{IP: ip, Family: "ipv6"})
	}
	sort.Slice(addresses, func(i, j int) bool {
		if addresses[i].Family != addresses[j].Family {
			return addresses[i].Family < addresses[j].Family
		}
		return addresses[i].IP < addresses[j].IP
	})
	addresses = deduplicateAddresses(addresses)
	result.ResolvedAddresses = addresses
	if len(addresses) == 0 {
		result.Error = "no IP addresses found"
		result.DurationMS = time.Since(started).Milliseconds()
		return result
	}
	totalChecks := len(addresses) * portCount
	if !fullScan {
		result.Results = make([]PortResult, 0, totalChecks)
		for _, address := range addresses {
			for _, port := range ports {
				result.Results = append(result.Results, PortResult{
					IP:          address.IP,
					Family:      address.Family,
					Port:        port,
					Status:      StateNotChecked,
					ServiceHint: serviceHints[port],
				})
			}
		}
	}

	jobs := make(chan checkJob)
	outcomes := make(chan checkOutcome, maxConcurrentChecks)
	workerCount := min(maxConcurrentChecks, totalChecks)
	var workers sync.WaitGroup
	workers.Add(workerCount)
	for range workerCount {
		go func() {
			defer workers.Done()
			for job := range jobs {
				if ctx.Err() != nil {
					continue
				}
				startedCheck := time.Now()
				checkCtx, cancel := context.WithTimeout(ctx, connectTimeout)
				connection, err := dialer.DialContext(checkCtx, "tcp", net.JoinHostPort(job.address.IP, strconv.Itoa(job.port)))
				cancel()
				check := PortResult{
					IP:            job.address.IP,
					Family:        job.address.Family,
					Port:          job.port,
					ConnectTimeMS: time.Since(startedCheck).Milliseconds(),
					ServiceHint:   serviceHints[job.port],
				}
				if err == nil {
					_ = connection.Close()
					check.Status = StateOpen
				} else {
					check.Error = err.Error()
					check.Status = classifyError(ctx, err)
				}
				outcomes <- checkOutcome{result: check, resultIndex: job.resultIndex}
			}
		}()
	}

	go func() {
		defer close(jobs)
		for addressIndex, address := range addresses {
			for portIndex := 0; portIndex < portCount; portIndex++ {
				port := portIndex + 1
				resultIndex := -1
				if !fullScan {
					port = ports[portIndex]
					resultIndex = addressIndex*portCount + portIndex
				}
				select {
				case jobs <- checkJob{address: address, port: port, resultIndex: resultIndex}:
				case <-ctx.Done():
					return
				}
			}
		}
	}()
	go func() {
		workers.Wait()
		close(outcomes)
	}()

	result.Summary.PortsPerAddress = portCount
	checkedAddresses := make(map[string]struct{}, len(addresses))
	attempted := 0
	for outcome := range outcomes {
		attempted++
		checkedAddresses[outcome.result.IP] = struct{}{}
		addOutcome(&result.Summary, outcome.result.Status)
		if fullScan {
			if outcome.result.Status == StateOpen {
				result.Results = append(result.Results, outcome.result)
			}
		} else {
			result.Results[outcome.resultIndex] = outcome.result
		}
	}
	result.Summary.AddressesChecked = len(checkedAddresses)
	result.Summary.NotChecked = totalChecks - attempted
	result.Complete = result.Error == "" && result.Summary.Timeout == 0 && result.Summary.Cancelled == 0 && result.Summary.Errors == 0 && result.Summary.NotChecked == 0
	sort.Slice(result.Results, func(i, j int) bool {
		if result.Results[i].Family != result.Results[j].Family {
			return result.Results[i].Family < result.Results[j].Family
		}
		if result.Results[i].IP != result.Results[j].IP {
			return result.Results[i].IP < result.Results[j].IP
		}
		return result.Results[i].Port < result.Results[j].Port
	})
	result.DurationMS = time.Since(started).Milliseconds()
	return result
}

func classifyError(ctx context.Context, err error) string {
	if errors.Is(err, context.DeadlineExceeded) {
		return StateTimeout
	}
	if errors.Is(err, context.Canceled) {
		return StateCancelled
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return StateTimeout
	}
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return StateTimeout
	}
	if errors.Is(ctx.Err(), context.Canceled) {
		return StateCancelled
	}
	if errors.Is(err, syscall.ECONNREFUSED) {
		return StateClosed
	}
	return StateError
}

func addOutcome(summary *Summary, status string) {
	switch status {
	case StateOpen:
		summary.Open++
	case StateClosed:
		summary.Closed++
	case StateTimeout:
		summary.Timeout++
	case StateCancelled:
		summary.Cancelled++
	default:
		summary.Errors++
	}
}

func deduplicateAddresses(addresses []Address) []Address {
	unique := addresses[:0]
	seen := make(map[string]struct{}, len(addresses))
	for _, address := range addresses {
		key := address.Family + ":" + address.IP
		if _, exists := seen[key]; exists {
			continue
		}
		seen[key] = struct{}{}
		unique = append(unique, address)
	}
	return unique
}
