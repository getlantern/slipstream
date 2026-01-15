package transport

import (
	"context"
	"io"
)

const (
	// ALPN is the application layer protocol negotiation string
	ALPN = "picoquic_sample"
	// SNI is the server name indication
	SNI = "test.example.com"
)

// StreamHandler handles incoming QUIC streams
type StreamHandler interface {
	HandleStream(ctx context.Context, stream io.ReadWriteCloser) error
}

// StreamHandlerFunc is a function adapter for StreamHandler
type StreamHandlerFunc func(ctx context.Context, stream io.ReadWriteCloser) error

func (f StreamHandlerFunc) HandleStream(ctx context.Context, stream io.ReadWriteCloser) error {
	return f(ctx, stream)
}
