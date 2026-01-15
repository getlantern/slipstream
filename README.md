# Slipstream - Go Implementation

A Go port of [slipstream](https://github.com/EndPositive/slipstream), a high-performance covert channel over DNS, powered by QUIC multipath. Because quic-go does not support multipath, this port does not include the multipath optimizations in Slipstream and only benefits from the reduced header sizes in QUIC vs the nested headers in DNSTT.

## Overview

Slipstream is a DNS tunneling tool that provides:
- **Adaptive congestion control** designed for rate-limited resolvers
- **QUIC-based transport** for reliable communication
- **60% lower header overhead** than traditional DNS tunneling tools

This implementation uses Go's excellent networking libraries and the quic-go implementation for robust, high-performance DNS tunneling.

## Architecture

The system consists of two components:

### Client
- Listens for TCP connections on a local port
- Encodes data as base32 and wraps it in DNS TXT queries
- Sends queries over QUIC streams to the server
- Receives responses containing tunneled data

### Server
- Listens for QUIC connections
- Decodes DNS queries to extract tunneled data
- Connects to upstream target (e.g., web server)
- Proxies bidirectional traffic between QUIC streams and TCP connections

## Building

```bash
cd slipstream

# Build client
go build -o bin/slipstream-client ./cmd/slipstream-client

# Build server
go build -o bin/slipstream-server ./cmd/slipstream-server
```

## Usage

### Server

Start the server to listen for incoming QUIC connections and proxy them to a target:

```bash
./bin/slipstream-server \
  --listen 0.0.0.0:4443 \
  --target localhost:8000 \
  --domain tunnel.example.com
```

**Options:**
- `-l, --listen`: Address to listen on (default: `0.0.0.0:4443`)
- `-t, --target`: Target address to proxy connections to (required)
- `-d, --domain`: Domain name for DNS tunneling (default: `tunnel.example.com`)
- `-c, --cert`: TLS certificate file (optional, generates self-signed if not provided)
- `-k, --key`: TLS key file (optional)

### Client

Start the client to create a local TCP proxy that tunnels through DNS:

```bash
./bin/slipstream-client \
  --listen 127.0.0.1:8080 \
  --server server.example.com:4443 \
  --domain tunnel.example.com
```

**Options:**
- `-l, --listen`: Local TCP address to listen on (default: `127.0.0.1:8080`)
- `-s, --server`: Server address (required)
- `-d, --domain`: Domain name for DNS tunneling (default: `tunnel.example.com`)

### Example Workflow

1. Start a web server on the server machine:
   ```bash
   python3 -m http.server 8000
   ```

2. Start the slipstream server:
   ```bash
   ./bin/slipstream-server -t localhost:8000 -l 0.0.0.0:4443
   ```

3. Start the slipstream client on another machine:
   ```bash
   ./bin/slipstream-client -s server.example.com:4443 -l 127.0.0.1:8080
   ```

4. Access the tunneled service:
   ```bash
   curl http://127.0.0.1:8080
   ```

## How It Works

### Data Flow (Client → Server)

1. Client receives TCP connection
2. Client reads data from TCP connection
3. Client encodes data as base32
4. Client formats base32 string as DNS labels (63 chars max per label)
5. Client creates DNS TXT query with encoded subdomain
6. Client sends DNS query over QUIC stream
7. Server receives QUIC data and parses DNS query
8. Server decodes base32 subdomain to get original data
9. Server forwards data to upstream target

### Data Flow (Server → Client)

1. Server receives data from upstream target
2. Server encodes data in DNS TXT response
3. Server sends DNS response over QUIC stream
4. Client receives QUIC data and parses DNS response
5. Client extracts data from TXT records
6. Client writes data to TCP connection

## Protocol Details

### DNS Encoding

- Data is encoded using base32 (RFC 4648) without padding
- Encoded string is split into DNS labels (max 63 characters each)
- Labels are joined with dots to form a subdomain
- Full domain format: `{base32-encoded-data}.{domain}`

### QUIC Configuration

- ALPN: `picoquic_sample`
- SNI: `test.example.com`
- Supports datagrams for potential optimization
- Self-signed certificates generated automatically

### DNS Packet Format

**Query (Client → Server):**
```
Question: {encoded-subdomain}.{domain}. TXT
EDNS: Buffer size 1232 bytes
```

**Response (Server → Client):**
```
Answer: TXT records containing tunneled data
TTL: 60 seconds
Split into 255-byte chunks per TXT record
```

## Project Structure

```
slipstream/
├── cmd/
│   ├── slipstream-client/    # Client CLI application
│   └── slipstream-server/    # Server CLI application
├── pkg/
│   ├── dns/                  # DNS encoding/decoding
│   │   ├── encoding.go       # Base32 subdomain encoding
│   │   └── packet.go         # DNS packet creation/parsing
│   ├── transport/            # QUIC transport layer
│   │   ├── types.go          # Common types
│   │   ├── client.go         # QUIC client
│   │   └── server.go         # QUIC server
│   └── proxy/                # TCP proxy functionality
│       └── proxy.go          # Bidirectional proxying
├── go.mod
└── README.md
```

## Dependencies

- [quic-go](https://github.com/quic-go/quic-go) - QUIC implementation in Go
- [miekg/dns](https://github.com/miekg/dns) - DNS library in Go
- [cobra](https://github.com/spf13/cobra) - CLI framework

## Security Considerations

**Warning:** This tool is intended for authorized security testing, research, and educational purposes only.

- Default configuration uses self-signed certificates (bypass with `InsecureSkipVerify`)
- For production use, provide proper TLS certificates
- DNS tunneling may violate network policies - ensure proper authorization
- Performance depends on DNS resolver rate limits and network conditions

## Performance

Performance characteristics depend on several factors:
- DNS resolver rate limits
- Network latency
- QUIC congestion control
- Payload size and encoding overhead

The Go implementation provides excellent concurrency through goroutines and should perform comparably to the C implementation for most use cases.

## Contributing

Contributions welcome! This is a port of the original C implementation to Go. Areas for improvement:

- [ ] Multiple resolver support (multipath)
- [ ] Custom congestion control algorithms
- [ ] Performance benchmarking and optimization
- [ ] Better error handling and logging
- [ ] Configuration file support
- [ ] Statistics and monitoring

## License

This implementation follows the original project's Apache-2.0 license.

## Acknowledgments

- Original [slipstream](https://github.com/EndPositive/slipstream) project by EndPositive
- Inspired by David Fifield's DNSTT and Turbo Tunnel concepts
- Built with Go's excellent networking and QUIC implementations

## References

- Original Slipstream: https://github.com/EndPositive/slipstream
- Documentation: https://endpositive.github.io/slipstream
- DNSTT: https://github.com/net4people/bbs/issues/51
