package dns

import (
	"fmt"

	"github.com/miekg/dns"
)

const (
	// DefaultTTL is the default TTL for DNS responses (60 seconds)
	DefaultTTL = 60
	// EDNSBufferSize is the EDNS UDP buffer size (1232 bytes)
	EDNSBufferSize = 1232
)

// CreateQuery creates a DNS TXT query for the given data encoded as a subdomain
func CreateQuery(data []byte, domain string) (*dns.Msg, error) {
	msg := new(dns.Msg)
	msg.SetQuestion(CreateFQDN(EncodeSubdomain(data), domain), dns.TypeTXT)
	msg.RecursionDesired = true

	// Add EDNS support for larger UDP payloads
	opt := &dns.OPT{
		Hdr: dns.RR_Header{
			Name:   ".",
			Rrtype: dns.TypeOPT,
		},
	}
	opt.SetUDPSize(EDNSBufferSize)
	msg.Extra = append(msg.Extra, opt)

	return msg, nil
}

// ParseQueryData extracts the tunneled data from a DNS query
func ParseQueryData(msg *dns.Msg, domain string) ([]byte, error) {
	if len(msg.Question) != 1 {
		return nil, fmt.Errorf("expected exactly 1 question, got %d", len(msg.Question))
	}

	question := msg.Question[0]
	if question.Qtype != dns.TypeTXT {
		return nil, fmt.Errorf("expected TXT query, got type %d", question.Qtype)
	}

	// Extract subdomain from FQDN
	subdomain, err := ExtractSubdomain(question.Name, domain)
	if err != nil {
		return nil, fmt.Errorf("failed to extract subdomain: %w", err)
	}

	// Decode subdomain to get original data
	if subdomain == "" {
		return []byte{}, nil
	}

	data, err := DecodeSubdomain(subdomain)
	if err != nil {
		return nil, fmt.Errorf("failed to decode subdomain: %w", err)
	}

	return data, nil
}

// CreateResponse creates a DNS TXT response containing the provided data
func CreateResponse(query *dns.Msg, data []byte) *dns.Msg {
	msg := new(dns.Msg)
	msg.SetReply(query)

	// If no data, return NXDOMAIN (name error)
	if len(data) == 0 {
		msg.Rcode = dns.RcodeNameError
		return msg
	}

	// Create TXT record with the data
	// Split data into 255-byte chunks as required by TXT record format
	var txtStrings []string
	for len(data) > 0 {
		chunkSize := 255
		if len(data) < chunkSize {
			chunkSize = len(data)
		}
		txtStrings = append(txtStrings, string(data[:chunkSize]))
		data = data[chunkSize:]
	}

	txt := &dns.TXT{
		Hdr: dns.RR_Header{
			Name:   query.Question[0].Name,
			Rrtype: dns.TypeTXT,
			Class:  dns.ClassINET,
			Ttl:    DefaultTTL,
		},
		Txt: txtStrings,
	}

	msg.Answer = append(msg.Answer, txt)

	// Copy EDNS from query if present
	if opt := query.IsEdns0(); opt != nil {
		msg.Extra = append(msg.Extra, opt)
	}

	return msg
}

// ParseResponseData extracts the tunneled data from a DNS response
func ParseResponseData(msg *dns.Msg) ([]byte, error) {
	// Check for error response codes
	if msg.Rcode == dns.RcodeNameError {
		// NXDOMAIN means no data to send
		return []byte{}, nil
	}

	if msg.Rcode != dns.RcodeSuccess {
		return nil, fmt.Errorf("DNS response error: %s", dns.RcodeToString[msg.Rcode])
	}

	// Extract data from TXT records
	var data []byte
	for _, answer := range msg.Answer {
		if txt, ok := answer.(*dns.TXT); ok {
			for _, s := range txt.Txt {
				data = append(data, []byte(s)...)
			}
		}
	}

	return data, nil
}

// CreateErrorResponse creates a DNS error response with the given rcode
func CreateErrorResponse(query *dns.Msg, rcode int) *dns.Msg {
	msg := new(dns.Msg)
	msg.SetReply(query)
	msg.Rcode = rcode
	return msg
}
