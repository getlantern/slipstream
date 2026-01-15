package dns

import (
	"encoding/base32"
	"fmt"
	"strings"
)

const (
	// MaxLabelLength is the maximum length of a DNS label (63 bytes)
	MaxLabelLength = 63
	// MaxDomainLength is the maximum length of a full DNS domain name (253 bytes)
	MaxDomainLength = 253
)

// Base32Encoding is the base32 encoding scheme used for DNS subdomain encoding
var Base32Encoding = base32.StdEncoding.WithPadding(base32.NoPadding)

// EncodeSubdomain encodes binary data into a DNS-safe subdomain using base32 encoding
// and splits it into DNS labels of appropriate length.
func EncodeSubdomain(data []byte) string {
	if len(data) == 0 {
		return ""
	}

	// Encode data as base32 (lowercase for DNS compatibility)
	encoded := strings.ToLower(Base32Encoding.EncodeToString(data))

	// Split into DNS labels (max 63 characters each)
	var labels []string
	for len(encoded) > 0 {
		labelLen := MaxLabelLength
		if len(encoded) < labelLen {
			labelLen = len(encoded)
		}
		labels = append(labels, encoded[:labelLen])
		encoded = encoded[labelLen:]
	}

	return strings.Join(labels, ".")
}

// DecodeSubdomain decodes a DNS subdomain back to binary data
func DecodeSubdomain(subdomain string) ([]byte, error) {
	// Remove dots to get the full base32 string
	encoded := strings.ReplaceAll(subdomain, ".", "")

	// Decode from base32
	decoded, err := Base32Encoding.DecodeString(strings.ToUpper(encoded))
	if err != nil {
		return nil, fmt.Errorf("failed to decode base32: %w", err)
	}

	return decoded, nil
}

// CreateFQDN creates a fully qualified domain name from a subdomain and domain
func CreateFQDN(subdomain, domain string) string {
	if subdomain == "" {
		return domain + "."
	}
	return subdomain + "." + domain + "."
}

// ExtractSubdomain extracts the subdomain portion from a FQDN
func ExtractSubdomain(fqdn, domain string) (string, error) {
	// Remove trailing dot if present
	fqdn = strings.TrimSuffix(fqdn, ".")
	domain = strings.TrimSuffix(domain, ".")

	// Check if the FQDN ends with the domain
	if !strings.HasSuffix(fqdn, "."+domain) && fqdn != domain {
		return "", fmt.Errorf("FQDN %s does not match domain %s", fqdn, domain)
	}

	// Extract subdomain
	if fqdn == domain {
		return "", nil
	}

	subdomain := strings.TrimSuffix(fqdn, "."+domain)
	return subdomain, nil
}

// CalculateMaxPayloadSize calculates the maximum payload size that can be encoded
// in a DNS query given the domain name length
func CalculateMaxPayloadSize(domainLen int) int {
	// Reserve space for: subdomain + "." + domain + "."
	// DNS name max length is 253, need at least 1 char for subdomain
	availableLen := MaxDomainLength - domainLen - 2 // -2 for dots

	// Account for base32 encoding overhead (5 bytes -> 8 characters)
	// Each base32 character represents 5 bits
	maxBase32Chars := availableLen
	maxPayloadBytes := (maxBase32Chars * 5) / 8

	return maxPayloadBytes
}
