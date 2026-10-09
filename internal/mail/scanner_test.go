package mail

import (
	"context"
	"errors"
	"testing"

	"github.com/miekg/dns"
)

func TestScanQueriesMXSPFAndDMARC(t *testing.T) {
	var queried []string
	query := func(_ context.Context, name string, qtype uint16, _ string) ([]dns.RR, int, error) {
		queried = append(queried, name)
		switch {
		case name == "example.com" && qtype == dns.TypeMX:
			return []dns.RR{&dns.MX{Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeMX}, Mx: "mail.example.com.", Preference: 10}}, dns.RcodeSuccess, nil
		case name == "example.com" && qtype == dns.TypeTXT:
			return []dns.RR{txtRR(name, "v=spf1 -all"), txtRR(name, "google-site-verification=token")}, dns.RcodeSuccess, nil
		case name == "_dmarc.example.com" && qtype == dns.TypeTXT:
			return []dns.RR{txtRR(name, "v=DMARC1; p=reject; rua=mailto:dmarc@example.com")}, dns.RcodeSuccess, nil
		default:
			t.Fatalf("unexpected DNS query %s type %d", name, qtype)
			return nil, 0, nil
		}
	}

	result := scan(context.Background(), "example.com", "127.0.0.1:53", query)
	if result.MX.Status != StatusConfigured || result.SPF.Status != StatusConfigured || result.DMARC.Status != StatusConfigured {
		t.Fatalf("unexpected statuses: MX=%s SPF=%s DMARC=%s", result.MX.Status, result.SPF.Status, result.DMARC.Status)
	}
	if result.DMARC.Policy != "reject" {
		t.Errorf("DMARC policy = %q, want reject", result.DMARC.Policy)
	}
	if len(queried) != 3 || queried[2] != "_dmarc.example.com" {
		t.Fatalf("queries = %v, want root MX/TXT and _dmarc TXT", queried)
	}
}

func TestScanDistinguishesMissingAndQueryErrors(t *testing.T) {
	query := func(_ context.Context, name string, _ uint16, _ string) ([]dns.RR, int, error) {
		if name == "_dmarc.example.com" {
			return nil, dns.RcodeServerFailure, nil
		}
		return nil, dns.RcodeNameError, nil
	}
	result := scan(context.Background(), "example.com", "", query)
	if result.MX.Status != StatusMissing || result.SPF.Status != StatusMissing {
		t.Fatalf("MX/SPF statuses = %s/%s, want missing/missing", result.MX.Status, result.SPF.Status)
	}
	if result.DMARC.Status != StatusIndeterminate {
		t.Fatalf("DMARC status = %s, want indeterminate", result.DMARC.Status)
	}
}

func TestInspectMailRecordsDetectsDuplicatesAndNullMX(t *testing.T) {
	spf := inspectSPF([]string{"v=spf1 -all", "v=spf1 ~all"}, "", "")
	if spf.Status != StatusMultiple || len(spf.Records) != 2 {
		t.Fatalf("SPF = %#v, want multiple policies", spf)
	}

	dmarc := inspectDMARC([]string{"v=DMARC1; p=none", "v=DMARC1; p=reject"}, "", "")
	if dmarc.Status != StatusMultiple {
		t.Fatalf("DMARC status = %s, want multiple", dmarc.Status)
	}

	nullMX := inspectMX([]dns.RR{&dns.MX{Hdr: dns.RR_Header{Rrtype: dns.TypeMX}, Mx: ".", Preference: 0}}, "", "")
	if nullMX.Status != StatusDisabled {
		t.Fatalf("Null MX status = %s, want disabled", nullMX.Status)
	}
}

func TestScanMarksTransportErrorsIndeterminate(t *testing.T) {
	query := func(context.Context, string, uint16, string) ([]dns.RR, int, error) {
		return nil, 0, errors.New("lookup timeout")
	}
	result := scan(context.Background(), "example.com", "", query)
	if result.MX.Status != StatusIndeterminate || result.SPF.Status != StatusIndeterminate || result.DMARC.Status != StatusIndeterminate {
		t.Fatalf("statuses = %s/%s/%s, want all indeterminate", result.MX.Status, result.SPF.Status, result.DMARC.Status)
	}
}

func txtRR(name, record string) *dns.TXT {
	return &dns.TXT{Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeTXT}, Txt: []string{record}}
}
