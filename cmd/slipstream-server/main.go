package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/spf13/cobra"

	"github.com/getlantern/lantern/slipstream/pkg/proxy"
	"github.com/getlantern/lantern/slipstream/pkg/transport"
)

var (
	listenAddr string
	targetAddr string
	domain     string
	certFile   string
	keyFile    string
)

var rootCmd = &cobra.Command{
	Use:   "slipstream-server",
	Short: "Slipstream DNS tunnel server",
	Long: `A high-performance covert channel over DNS, powered by QUIC multipath.
The server receives DNS queries over QUIC and forwards connections to the target.`,
	RunE: runServer,
}

func init() {
	rootCmd.Flags().StringVarP(&listenAddr, "listen", "l", "0.0.0.0:4443", "Server address to listen on")
	rootCmd.Flags().StringVarP(&targetAddr, "target", "t", "", "Target address to proxy connections to (host:port)")
	rootCmd.Flags().StringVarP(&domain, "domain", "d", "tunnel.example.com", "Domain name for DNS tunneling")
	rootCmd.Flags().StringVarP(&certFile, "cert", "c", "", "TLS certificate file (optional, generates self-signed if not provided)")
	rootCmd.Flags().StringVarP(&keyFile, "key", "k", "", "TLS key file (optional)")

	rootCmd.MarkFlagRequired("target")
}

func runServer(cmd *cobra.Command, args []string) error {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Setup signal handling
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	// Create server proxy handler
	handler := proxy.NewServerProxy(targetAddr)

	// Create QUIC server
	server, err := transport.NewServer(listenAddr, domain, handler)
	if err != nil {
		return fmt.Errorf("failed to create server: %w", err)
	}

	// Load custom TLS certificates if provided
	if certFile != "" && keyFile != "" {
		log.Printf("Loading TLS certificates from %s and %s", certFile, keyFile)
		if err := server.SetTLSConfig(certFile, keyFile); err != nil {
			return fmt.Errorf("failed to load TLS config: %w", err)
		}
	} else {
		log.Printf("Using self-signed TLS certificate")
	}

	// Start server in goroutine
	errChan := make(chan error, 1)
	go func() {
		log.Printf("Starting server on %s, proxying to %s", listenAddr, targetAddr)
		errChan <- server.Listen(ctx)
	}()

	// Wait for signal or error
	select {
	case sig := <-sigChan:
		log.Printf("Received signal %v, shutting down...", sig)
		cancel()
		return nil
	case err := <-errChan:
		if err != nil && err != context.Canceled {
			return fmt.Errorf("server error: %w", err)
		}
		return nil
	}
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
