package mail

import (
	"context"
	"fmt"
	"strings"
	"time"

	dnsquery "github.com/gqrdev/gqrnet-cli/internal/dns"
	"github.com/miekg/dns"
)

type queryFunc func(context.Context, string, uint16, string) ([]dns.RR, int, error)

// Scan inspects MX, SPF, and DMARC records using the selected DNS server.
func Scan(ctx context.Context, domain, server string) Result {
	return scan(ctx, domain, server, dnsquery.QueryRecords)
}

func scan(ctx context.Context, domain, server string, query queryFunc) Result {
	started := time.Now()
	result := Result{Domain: domain}

	mxRecords, mxStatus, mxDetail := lookup(ctx, domain, dns.TypeMX, server, query)
	result.MX = inspectMX(mxRecords, mxStatus, mxDetail)

	spfAnswers, spfStatus, spfDetail := lookup(ctx, domain, dns.TypeTXT, server, query)
	result.SPF = inspectSPF(txtRecords(spfAnswers), spfStatus, spfDetail)

	dmarcAnswers, dmarcStatus, dmarcDetail := lookup(ctx, "_dmarc."+domain, dns.TypeTXT, server, query)
	result.DMARC = inspectDMARC(txtRecords(dmarcAnswers), dmarcStatus, dmarcDetail)

	result.DurationMS = time.Since(started).Milliseconds()
	return result
}

func lookup(ctx context.Context, name string, qtype uint16, server string, query queryFunc) ([]dns.RR, string, string) {
	answers, rcode, err := query(ctx, name, qtype, server)
	if err != nil {
		return nil, StatusIndeterminate, "DNS query failed: " + err.Error()
	}
	switch rcode {
	case dns.RcodeSuccess:
		return answers, "", ""
	case dns.RcodeNameError:
		return nil, StatusMissing, "DNS name does not exist"
	default:
		rcodeName, ok := dns.RcodeToString[rcode]
		if !ok {
			rcodeName = fmt.Sprintf("RCODE%d", rcode)
		}
		return nil, StatusIndeterminate, "DNS server returned " + rcodeName
	}
}

func inspectMX(answers []dns.RR, status, detail string) CheckResult {
	if status != "" {
		return CheckResult{Status: status, Detail: detail}
	}
	var records []string
	var nullMX bool
	for _, answer := range answers {
		mx, ok := answer.(*dns.MX)
		if !ok {
			continue
		}
		records = append(records, fmt.Sprintf("%s (%d)", mx.Mx, mx.Preference))
		if mx.Mx == "." && mx.Preference == 0 {
			nullMX = true
		}
	}
	if len(records) == 0 {
		return CheckResult{Status: StatusMissing, Detail: "no MX records found"}
	}
	if nullMX {
		if len(records) == 1 {
			return CheckResult{Status: StatusDisabled, Records: records, Detail: "Null MX explicitly indicates that the domain does not accept email"}
		}
		return CheckResult{Status: StatusInvalid, Records: records, Detail: "Null MX must not be published alongside other MX records"}
	}
	return CheckResult{Status: StatusConfigured, Records: records}
}

func inspectSPF(records []string, status, detail string) CheckResult {
	if status != "" {
		return CheckResult{Status: status, Detail: detail}
	}
	var policies []string
	for _, record := range records {
		if hasVersionTag(record, "v=spf1") {
			policies = append(policies, record)
		}
	}
	if len(policies) == 0 {
		return CheckResult{Status: StatusMissing, Detail: "no SPF record found"}
	}
	if len(policies) > 1 {
		return CheckResult{Status: StatusMultiple, Records: policies, Detail: "multiple SPF records were found"}
	}
	return CheckResult{Status: StatusConfigured, Records: policies}
}

func inspectDMARC(records []string, status, detail string) CheckResult {
	if status != "" {
		return CheckResult{Status: status, Detail: detail}
	}
	var policies []string
	for _, record := range records {
		if hasVersionTag(record, "v=DMARC1") {
			policies = append(policies, record)
		}
	}
	if len(policies) == 0 {
		return CheckResult{Status: StatusMissing, Detail: "no DMARC record found"}
	}
	if len(policies) > 1 {
		return CheckResult{Status: StatusMultiple, Records: policies, Detail: "multiple DMARC records were found"}
	}
	policy, valid := dmarcPolicy(policies[0])
	if !valid {
		return CheckResult{Status: StatusInvalid, Records: policies, Detail: "DMARC record must contain one valid p tag"}
	}
	return CheckResult{Status: StatusConfigured, Records: policies, Policy: policy}
}

func txtRecords(answers []dns.RR) []string {
	var records []string
	for _, answer := range answers {
		if txt, ok := answer.(*dns.TXT); ok {
			records = append(records, strings.Join(txt.Txt, " "))
		}
	}
	return records
}

func hasVersionTag(record, version string) bool {
	fields := strings.Fields(strings.TrimSpace(record))
	return len(fields) > 0 && strings.EqualFold(strings.TrimSuffix(fields[0], ";"), version)
}

func dmarcPolicy(record string) (string, bool) {
	var policy string
	count := 0
	for _, part := range strings.Split(record, ";") {
		key, value, found := strings.Cut(part, "=")
		if found && strings.EqualFold(strings.TrimSpace(key), "p") {
			count++
			policy = strings.ToLower(strings.TrimSpace(value))
		}
	}
	if count != 1 || (policy != "none" && policy != "quarantine" && policy != "reject") {
		return "", false
	}
	return policy, true
}
