package dns

import (
	"context"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	mdns "github.com/miekg/dns"
)

func TestQueryDNSWithOptionsKeepsSuccessfulTypesAndReportsRcode(t *testing.T) {
	packetConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket returned error: %v", err)
	}

	var mu sync.Mutex
	queries := make(map[uint16]int)
	server := &mdns.Server{
		PacketConn: packetConn,
		Handler: mdns.HandlerFunc(func(w mdns.ResponseWriter, request *mdns.Msg) {
			question := request.Question[0]
			mu.Lock()
			queries[question.Qtype]++
			mu.Unlock()

			response := new(mdns.Msg)
			response.SetReply(request)
			switch question.Qtype {
			case mdns.TypeA:
				response.Answer = append(response.Answer, &mdns.A{
					Hdr: mdns.RR_Header{
						Name:   question.Name,
						Rrtype: mdns.TypeA,
						Class:  mdns.ClassINET,
						Ttl:    60,
					},
					A: net.ParseIP("192.0.2.1").To4(),
				})
			case mdns.TypeMX:
				response.Rcode = mdns.RcodeNameError
			}
			_ = w.WriteMsg(response)
		}),
	}
	go func() {
		_ = server.ActivateAndServe()
	}()
	t.Cleanup(func() { _ = server.Shutdown() })

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	result := QueryDNSWithOptions(ctx, "example.com", Options{
		Server: packetConn.LocalAddr().String(),
		Types:  []uint16{mdns.TypeA, mdns.TypeMX},
	})

	if len(result.A) != 1 || result.A[0] != "192.0.2.1" {
		t.Fatalf("A records = %v, want [192.0.2.1]", result.A)
	}
	if !strings.Contains(result.Error, "MX: DNS server returned NXDOMAIN") {
		t.Fatalf("error = %q, want MX NXDOMAIN", result.Error)
	}

	mu.Lock()
	defer mu.Unlock()
	if queries[mdns.TypeA] != 1 || queries[mdns.TypeMX] != 1 {
		t.Fatalf("query counts = %#v, want one A and one MX query", queries)
	}
}

func TestQueryRecordsReturnsRcodeSeparately(t *testing.T) {
	packetConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket returned error: %v", err)
	}
	server := &mdns.Server{
		PacketConn: packetConn,
		Handler: mdns.HandlerFunc(func(w mdns.ResponseWriter, request *mdns.Msg) {
			response := new(mdns.Msg)
			response.SetReply(request)
			if request.Question[0].Name == "missing.example." {
				response.Rcode = mdns.RcodeNameError
			}
			_ = w.WriteMsg(response)
		}),
	}
	go func() {
		_ = server.ActivateAndServe()
	}()
	t.Cleanup(func() { _ = server.Shutdown() })

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	for _, test := range []struct {
		name      string
		wantRcode int
	}{
		{name: "missing.example", wantRcode: mdns.RcodeNameError},
		{name: "nodata.example", wantRcode: mdns.RcodeSuccess},
	} {
		t.Run(test.name, func(t *testing.T) {
			answers, rcode, err := QueryRecords(ctx, test.name, mdns.TypeTXT, packetConn.LocalAddr().String())
			if err != nil {
				t.Fatalf("QueryRecords returned error: %v", err)
			}
			if rcode != test.wantRcode {
				t.Fatalf("rcode = %d, want %d", rcode, test.wantRcode)
			}
			if len(answers) != 0 {
				t.Fatalf("answers = %v, want none", answers)
			}
		})
	}
}

func TestQueryRecordsRetriesTruncatedResponseOverTCP(t *testing.T) {
	packetConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket returned error: %v", err)
	}
	tcpListener, err := net.Listen("tcp", packetConn.LocalAddr().String())
	if err != nil {
		_ = packetConn.Close()
		t.Fatalf("Listen returned error: %v", err)
	}
	handler := mdns.HandlerFunc(func(w mdns.ResponseWriter, request *mdns.Msg) {
		response := new(mdns.Msg)
		response.SetReply(request)
		if w.LocalAddr().Network() == "udp" {
			response.Truncated = true
		} else {
			response.Answer = append(response.Answer, &mdns.TXT{
				Hdr: mdns.RR_Header{Name: request.Question[0].Name, Rrtype: mdns.TypeTXT, Class: mdns.ClassINET, Ttl: 60},
				Txt: []string{"v=spf1 -all"},
			})
		}
		_ = w.WriteMsg(response)
	})
	udpServer := &mdns.Server{PacketConn: packetConn, Handler: handler}
	tcpServer := &mdns.Server{Listener: tcpListener, Handler: handler}
	go func() { _ = udpServer.ActivateAndServe() }()
	go func() { _ = tcpServer.ActivateAndServe() }()
	t.Cleanup(func() {
		_ = udpServer.Shutdown()
		_ = tcpServer.Shutdown()
	})

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	answers, rcode, err := QueryRecords(ctx, "example.com", mdns.TypeTXT, packetConn.LocalAddr().String())
	if err != nil {
		t.Fatalf("QueryRecords returned error: %v", err)
	}
	if rcode != mdns.RcodeSuccess || len(answers) != 1 {
		t.Fatalf("rcode/answers = %d/%v, want success and one answer", rcode, answers)
	}
}
