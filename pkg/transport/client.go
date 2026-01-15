package transport

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"sync"

	"github.com/miekg/dns"
	"github.com/quic-go/quic-go"

	dnspkg "github.com/getlantern/lantern/slipstream/pkg/dns"
)

// Client represents a slipstream QUIC client
type Client struct {
	serverAddr string
	domain     string
	tlsConfig  *tls.Config
	quicConfig *quic.Config
	conn       quic.Connection
	mu         sync.RWMutex
}

// NewClient creates a new slipstream client
func NewClient(serverAddr, domain string) *Client {
	return &Client{
		serverAddr: serverAddr,
		domain:     domain,
		tlsConfig: &tls.Config{
			InsecureSkipVerify: true, // TODO: Add proper certificate verification
			NextProtos:         []string{ALPN},
			ServerName:         SNI,
		},
		quicConfig: &quic.Config{
			EnableDatagrams: true,
			KeepAlivePeriod: 0, // Disable keep-alive by default
		},
	}
}

// Connect establishes a connection to the server
func (c *Client) Connect(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	conn, err := quic.DialAddr(ctx, c.serverAddr, c.tlsConfig, c.quicConfig)
	if err != nil {
		return fmt.Errorf("failed to connect to server: %w", err)
	}

	c.conn = conn
	log.Printf("Connected to server at %s", c.serverAddr)
	return nil
}

// OpenStream opens a new QUIC stream for proxying a connection
func (c *Client) OpenStream(ctx context.Context) (io.ReadWriteCloser, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.conn == nil {
		return nil, fmt.Errorf("not connected to server")
	}

	stream, err := c.conn.OpenStreamSync(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to open stream: %w", err)
	}

	return &dnsStream{
		stream: stream,
		domain: c.domain,
	}, nil
}

// Close closes the client connection
func (c *Client) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.conn != nil {
		return c.conn.CloseWithError(0, "client closing")
	}
	return nil
}

// dnsStream wraps a QUIC stream with DNS encoding/decoding
type dnsStream struct {
	stream quic.Stream
	domain string
}

func (ds *dnsStream) Read(p []byte) (int, error) {
	// For the client, we read QUIC data and decode it as DNS responses
	buf := make([]byte, 4096)
	n, err := ds.stream.Read(buf)
	if err != nil {
		return 0, err
	}

	// Parse DNS response
	msg := new(dns.Msg)
	if err := msg.Unpack(buf[:n]); err != nil {
		return 0, fmt.Errorf("failed to parse DNS response: %w", err)
	}

	// Extract data from response
	data, err := dnspkg.ParseResponseData(msg)
	if err != nil {
		return 0, fmt.Errorf("failed to extract data from DNS response: %w", err)
	}

	// Copy to output buffer
	copied := copy(p, data)
	return copied, nil
}

func (ds *dnsStream) Write(p []byte) (int, error) {
	// For the client, we encode data as DNS queries
	msg, err := dnspkg.CreateQuery(p, ds.domain)
	if err != nil {
		return 0, fmt.Errorf("failed to create DNS query: %w", err)
	}

	// Pack DNS message
	packed, err := msg.Pack()
	if err != nil {
		return 0, fmt.Errorf("failed to pack DNS query: %w", err)
	}

	// Write to QUIC stream
	_, err = ds.stream.Write(packed)
	if err != nil {
		return 0, err
	}

	return len(p), nil
}

func (ds *dnsStream) Close() error {
	return ds.stream.Close()
}
