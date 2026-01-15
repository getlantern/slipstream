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
	serverAddr string
	domain     string
)

var rootCmd = &cobra.Command{
	Use:   "slipstream-client",
	Short: "Slipstream DNS tunnel client",
	Long: `A high-performance covert channel over DNS, powered by QUIC multipath.
The client listens for TCP connections and tunnels them through DNS queries to the server.`,
	RunE: runClient,
}

func init() {
	rootCmd.Flags().StringVarP(&listenAddr, "listen", "l", "127.0.0.1:8080", "Local TCP address to listen on")
	rootCmd.Flags().StringVarP(&serverAddr, "server", "s", "", "Server address (host:port)")
	rootCmd.Flags().StringVarP(&domain, "domain", "d", "tunnel.example.com", "Domain name for DNS tunneling")

	rootCmd.MarkFlagRequired("server")
}

func runClient(cmd *cobra.Command, args []string) error {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Setup signal handling
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	// Create QUIC client
	client := transport.NewClient(serverAddr, domain)

	// Connect to server
	log.Printf("Connecting to server at %s...", serverAddr)
	if err := client.Connect(ctx); err != nil {
		return fmt.Errorf("failed to connect to server: %w", err)
	}
	defer client.Close()

	log.Printf("Connected to server")

	// Create TCP proxy
	tcpProxy := proxy.NewTCPProxy(listenAddr, client)

	// Start proxy in goroutine
	errChan := make(chan error, 1)
	go func() {
		errChan <- tcpProxy.Listen(ctx)
	}()

	// Wait for signal or error
	select {
	case sig := <-sigChan:
		log.Printf("Received signal %v, shutting down...", sig)
		cancel()
		tcpProxy.Close()
		return nil
	case err := <-errChan:
		if err != nil && err != context.Canceled {
			return fmt.Errorf("proxy error: %w", err)
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
