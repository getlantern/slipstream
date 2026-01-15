package proxy

import (
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"sync"
)

// TCPProxy handles proxying TCP connections through QUIC streams
type TCPProxy struct {
	listenAddr string
	client     StreamOpener
	listener   net.Listener
	wg         sync.WaitGroup
}

// StreamOpener opens new streams for proxying
type StreamOpener interface {
	OpenStream(ctx context.Context) (io.ReadWriteCloser, error)
}

// NewTCPProxy creates a new TCP proxy
func NewTCPProxy(listenAddr string, client StreamOpener) *TCPProxy {
	return &TCPProxy{
		listenAddr: listenAddr,
		client:     client,
	}
}

// Listen starts listening for TCP connections
func (p *TCPProxy) Listen(ctx context.Context) error {
	listener, err := net.Listen("tcp", p.listenAddr)
	if err != nil {
		return fmt.Errorf("failed to start TCP listener: %w", err)
	}
	p.listener = listener

	log.Printf("TCP proxy listening on %s", p.listenAddr)

	for {
		conn, err := listener.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return ctx.Err()
			default:
				log.Printf("Failed to accept TCP connection: %v", err)
				continue
			}
		}

		p.wg.Add(1)
		go p.handleConnection(ctx, conn)
	}
}

func (p *TCPProxy) handleConnection(ctx context.Context, conn net.Conn) {
	defer p.wg.Done()
	defer conn.Close()

	log.Printf("New TCP connection from %s", conn.RemoteAddr())

	// Open QUIC stream for this connection
	stream, err := p.client.OpenStream(ctx)
	if err != nil {
		log.Printf("Failed to open stream: %v", err)
		return
	}
	defer stream.Close()

	// Proxy data bidirectionally
	if err := BiDirectionalCopy(conn, stream); err != nil {
		log.Printf("Proxy error: %v", err)
	}

	log.Printf("Connection closed: %s", conn.RemoteAddr())
}

// Close closes the TCP proxy
func (p *TCPProxy) Close() error {
	if p.listener != nil {
		p.listener.Close()
	}
	p.wg.Wait()
	return nil
}

// ServerProxy handles server-side proxying to upstream targets
type ServerProxy struct {
	targetAddr string
}

// NewServerProxy creates a new server-side proxy
func NewServerProxy(targetAddr string) *ServerProxy {
	return &ServerProxy{
		targetAddr: targetAddr,
	}
}

// HandleStream handles a QUIC stream by connecting to the target
func (sp *ServerProxy) HandleStream(ctx context.Context, stream io.ReadWriteCloser) error {
	defer stream.Close()

	// Connect to upstream target
	conn, err := net.Dial("tcp", sp.targetAddr)
	if err != nil {
		return fmt.Errorf("failed to connect to target %s: %w", sp.targetAddr, err)
	}
	defer conn.Close()

	log.Printf("Proxying to %s", sp.targetAddr)

	// Proxy data bidirectionally
	if err := BiDirectionalCopy(stream, conn); err != nil {
		return fmt.Errorf("proxy error: %w", err)
	}

	return nil
}

// BiDirectionalCopy copies data bidirectionally between two ReadWriteClosers
func BiDirectionalCopy(a, b io.ReadWriteCloser) error {
	errChan := make(chan error, 2)

	copy := func(dst io.Writer, src io.Reader) {
		_, err := io.Copy(dst, src)
		errChan <- err
	}

	go copy(a, b)
	go copy(b, a)

	// Wait for first error (or EOF)
	err1 := <-errChan
	err2 := <-errChan

	// Return first non-EOF error
	if err1 != nil && err1 != io.EOF {
		return err1
	}
	if err2 != nil && err2 != io.EOF {
		return err2
	}

	return nil
}
