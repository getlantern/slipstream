package transport

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"log"
	"math/big"
	"time"

	"github.com/miekg/dns"
	"github.com/quic-go/quic-go"

	dnspkg "github.com/getlantern/lantern/slipstream/pkg/dns"
)

// Server represents a slipstream QUIC server
type Server struct {
	listenAddr string
	domain     string
	tlsConfig  *tls.Config
	quicConfig *quic.Config
	handler    StreamHandler
}

// NewServer creates a new slipstream server
func NewServer(listenAddr, domain string, handler StreamHandler) (*Server, error) {
	tlsConfig, err := generateTLSConfig()
	if err != nil {
		return nil, fmt.Errorf("failed to generate TLS config: %w", err)
	}

	return &Server{
		listenAddr: listenAddr,
		domain:     domain,
		tlsConfig:  tlsConfig,
		quicConfig: &quic.Config{
			EnableDatagrams: true,
		},
		handler: handler,
	}, nil
}

// SetTLSConfig sets custom TLS configuration (certificates)
func (s *Server) SetTLSConfig(certFile, keyFile string) error {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return fmt.Errorf("failed to load certificates: %w", err)
	}

	s.tlsConfig.Certificates = []tls.Certificate{cert}
	return nil
}

// Listen starts the server and handles incoming connections
func (s *Server) Listen(ctx context.Context) error {
	listener, err := quic.ListenAddr(s.listenAddr, s.tlsConfig, s.quicConfig)
	if err != nil {
		return fmt.Errorf("failed to start listener: %w", err)
	}
	defer listener.Close()

	log.Printf("Server listening on %s", s.listenAddr)

	for {
		conn, err := listener.Accept(ctx)
		if err != nil {
			select {
			case <-ctx.Done():
				return ctx.Err()
			default:
				log.Printf("Failed to accept connection: %v", err)
				continue
			}
		}

		go s.handleConnection(ctx, conn)
	}
}

func (s *Server) handleConnection(ctx context.Context, conn quic.Connection) {
	defer conn.CloseWithError(0, "connection closed")

	log.Printf("New connection from %s", conn.RemoteAddr())

	for {
		stream, err := conn.AcceptStream(ctx)
		if err != nil {
			select {
			case <-ctx.Done():
				return
			default:
				log.Printf("Failed to accept stream: %v", err)
				return
			}
		}

		go s.handleStream(ctx, stream)
	}
}

func (s *Server) handleStream(ctx context.Context, stream quic.Stream) {
	defer stream.Close()

	dnsStream := &serverDNSStream{
		stream: stream,
		domain: s.domain,
	}

	if err := s.handler.HandleStream(ctx, dnsStream); err != nil {
		log.Printf("Stream handler error: %v", err)
	}
}

// serverDNSStream wraps a QUIC stream with DNS encoding/decoding for server side
type serverDNSStream struct {
	stream quic.Stream
	domain string
}

func (ds *serverDNSStream) Read(p []byte) (int, error) {
	// For the server, we read QUIC data and decode it as DNS queries
	buf := make([]byte, 4096)
	n, err := ds.stream.Read(buf)
	if err != nil {
		return 0, err
	}

	// Parse DNS query
	msg := new(dns.Msg)
	if err := msg.Unpack(buf[:n]); err != nil {
		return 0, fmt.Errorf("failed to parse DNS query: %w", err)
	}

	// Extract data from query
	data, err := dnspkg.ParseQueryData(msg, ds.domain)
	if err != nil {
		return 0, fmt.Errorf("failed to extract data from DNS query: %w", err)
	}

	// Copy to output buffer
	copied := copy(p, data)
	return copied, nil
}

func (ds *serverDNSStream) Write(p []byte) (int, error) {
	// For the server, we encode data as DNS responses
	// We need to create a dummy query to respond to
	dummyQuery := new(dns.Msg)
	dummyQuery.SetQuestion(dnspkg.CreateFQDN("", ds.domain), dns.TypeTXT)

	msg := dnspkg.CreateResponse(dummyQuery, p)

	// Pack DNS message
	packed, err := msg.Pack()
	if err != nil {
		return 0, fmt.Errorf("failed to pack DNS response: %w", err)
	}

	// Write to QUIC stream
	_, err = ds.stream.Write(packed)
	if err != nil {
		return 0, err
	}

	return len(p), nil
}

func (ds *serverDNSStream) Close() error {
	return ds.stream.Close()
}

// generateTLSConfig generates a self-signed TLS certificate for testing
func generateTLSConfig() (*tls.Config, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: SNI,
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}

	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, err
	}

	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{ALPN},
	}, nil
}
