# Kali MCP Pentest Server

A Model Context Protocol (MCP) server that provides access to essential penetration testing tools through a standardized interface. Built on Kali Linux and designed for integration with AI assistants and automation platforms.

## Overview

This project packages essential security testing tools into an MCP server running in a containerized Kali Linux environment. It uses the FastMCP framework to expose security tools with proper input validation, timeout handling, and safety controls.

## Available Tools

The server provides the following security testing tools via MCP:

| Tool | Purpose | Parameter | Example Command |
|------|---------|-----------|-----------------|
| `nmap_scan` | Network port scanning | `target` (hostname/IP) | `nmap -Pn <target>` |
| `nikto_scan` | Web server vulnerability scanning | `target` (hostname/IP) | `nikto -h <target>` |
| `sqlmap_scan` | SQL injection testing | `target` (URL) | `sqlmap -u <target> --batch` |
| `wpscan_scan` | WordPress security scanning | `target` (WordPress URL) | `wpscan --url <target>` |
| `dirb_scan` | Directory/file enumeration | `target` (URL) | `dirb <target>` |
| `gobuster_dir_scan` | Directory/file brute force | `target` (URL) | `gobuster dir -u <target> -w seclists/common` |
| `gobuster_dns_scan` | DNS subdomain brute force | `target` (domain) | `gobuster dns -d <target> -w seclists/subdomains` |
| `gobuster_vhost_scan` | Virtual host brute force | `target` (URL) | `gobuster vhost -u <target> -w seclists/subdomains` |
| `searchsploit_query` | Exploit database search | `query` (search term) | `searchsploit <query>` |
| `sherlock_scan` | Username reconnaissance across social networks | `username` (username to search) | `sherlock --timeout 30 --print-found <username>` |
| `whatweb_scan` | Web technology identification | `target` (URL) | `whatweb --no-color <target>` |
| `ping_scan` | Network connectivity test | `target` (hostname/IP) | `ping -c 4 <target>` |
| `traceroute_scan` | Network path tracing | `target` (hostname/IP) | `traceroute <target>` |
| `hping3_ping_scan` | TCP connectivity test | `target` (hostname/IP) | `hping3 -c 4 -S -p 80 <target>` |
| `hping3_port_scan` | TCP port scanning | `target` (hostname/IP) | `hping3 -c 1 -S -p ++80 <target>` |
| `hping3_traceroute_scan` | TCP traceroute | `target` (hostname/IP) | `hping3 --traceroute -c 3 -S -p 80 <target>` |
| `arping_scan` | ARP ping for Layer 2 connectivity | `target` (hostname/IP) | `arping -c 4 <target>` |
| `photon_scan` | Web crawler for OSINT reconnaissance | `target` (URL) | `photon -u <target> -l 2 --only-urls --timeout 30` |

## Architecture

- **Base**: Kali Linux (`kalilinux/kali-rolling`) Docker container
- **Framework**: FastMCP for MCP protocol implementation
- **Transport**: StreamableHTTP (supports SSE and HTTP endpoints)
- **Security**: Non-root execution with minimal required capabilities
- **Dependencies**: Python virtual environment with required packages

## Quick Start

### Using Docker Compose (Recommended)

```bash
# Start the server
docker compose up -d

# View logs
docker compose logs -f

# Stop the server
docker compose down
```

### Using Docker

```bash
# Build the image
docker build -t kali-mcp-server .

# Run the container
docker run -p 8080:8080 \
  --cap-add=NET_RAW \
  --cap-add=NET_ADMIN \
  --cap-add=NET_BIND_SERVICE \
  kali-mcp-server
```

### Using Pre-built Image

```bash
# Pull and run the latest image from GitHub Container Registry
docker run -p 8080:8080 \
  --cap-add=NET_RAW \
  --cap-add=NET_ADMIN \
  --cap-add=NET_BIND_SERVICE \
  ghcr.io/andrew-stclair/kali-mcp-server/kali-mcp-server:latest
```

## MCP Integration

### Protocol Details

- **Server Name**: `kali-mcp-pentest-server`
- **Transport**: StreamableHTTP
- **Host**: `0.0.0.0`
- **Port**: `8080`
- **Endpoints**:
  - MCP Protocol: `http://localhost:8080/mcp`
  - Server-Sent Events: `http://localhost:8080/sse`
  - Status Check: `http://localhost:8080/`

### Client Configuration

For MCP clients like N8N:

```json
{
  "serverUrl": "http://localhost:8080",
  "transport": "http",
  "mcpPath": "/mcp"
}
```

### Testing MCP Connection

```bash
# Check server status
curl http://localhost:8080/

# Connect to SSE endpoint for session info
curl -H "Accept: text/event-stream" http://localhost:8080/sse
```

## Security Features

### Input Validation
- Sanitizes all user inputs to prevent command injection
- Blocks dangerous characters: `;&|$`\`\\n\\r`
- Validates tool names against allowed list

### Runtime Security
- Runs as non-root user (`kaliuser`)
- Uses Python virtual environment for dependency isolation
- Required Linux capabilities: `NET_RAW`, `NET_ADMIN`, `NET_BIND_SERVICE`
- Tool execution timeout: 120 seconds

### Tool Restrictions
- Only whitelisted tools can be executed
- Fixed command-line arguments prevent arbitrary command execution
- Subprocess isolation with proper error handling

## Development

### Local Development

```bash
# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Run the server
python main.py
```

### Dependencies

- `fastapi` - Web framework
- `uvicorn` - ASGI server
- `python-multipart` - Form data handling
- `mcp>=1.15.0` - Model Context Protocol implementation

### Testing

The project includes a comprehensive testing suite that validates all MCP tools and security features.

#### Quick Testing

```bash
# Install test dependencies
pip install -r requirements-test.txt

# Run all tests
pytest tests/ -v

# Run tests with coverage
pytest tests/ -v --cov=main --cov-report=term-missing
```

#### Using Make (Recommended)

```bash
# Install development environment
make install

# Run full test suite with coverage
make test

# Run tests without coverage (faster)
make test-fast

# Run linting
make lint

# Run security analysis
make security

# Run all CI/CD checks
make ci-test
```

#### Test Categories

The test suite includes:

- **Unit Tests** (`tests/test_utils.py`): Test core utility functions like input sanitization and tool execution
- **MCP Tool Tests** (`tests/test_mcp_tools.py`): Test all 18 MCP tool functions with mock execution
- **Server Integration Tests** (`tests/test_mcp_server.py`): Test MCP server initialization and configuration
- **End-to-End Integration Tests** (`tests/test_integration.py`): Test complete workflows and error handling

#### Test Coverage

- Maintains **97%+ code coverage** with a minimum threshold of 85%
- Tests all 18 security tools exposed via MCP protocol
- Validates input sanitization and command injection prevention
- Tests error handling for timeouts, permissions, and missing tools
- Ensures tool whitelisting security controls

#### GitHub Actions CI/CD

Tests run automatically on:
- Every push to the `main` branch
- Every pull request targeting the `main` branch
- Supports Python 3.11 and 3.12
- Includes security scanning with bandit
- Generates coverage reports

### Container Build Process

The Dockerfile performs these steps:

1. Starts with Kali Linux rolling release
2. Installs security tools and Python dependencies
3. Creates non-root user with sudo privileges
4. Sets up proper file ownership and capabilities
5. Creates Python virtual environment
6. Installs Python packages in isolated environment
7. Exposes port 8080 and runs the MCP server

## CI/CD Pipeline

The GitHub Actions workflow (`.github/workflows/docker-build.yml`):

- **Triggers**: Push to `main` branch (after PR merge), weekly schedule (Sundays at 2:00 AM UTC)
- **Build**: Multi-architecture (linux/amd64, linux/arm64)
- **Registry**: GitHub Container Registry (`ghcr.io`)
- **Deployment**: Automatic on merge to `main` or weekly schedule

## Security Considerations

⚠️ **Educational Use Only**: This tool is intended for learning and authorized testing only.

### Important Notes

- Always obtain proper authorization before testing targets
- Use only on systems you own or have explicit permission to test
- The container requires elevated network capabilities for certain tools
- Input validation helps prevent command injection but shouldn't be your only security layer
- Monitor logs for suspicious activity

### Capabilities Required

The container needs these Linux capabilities:
- `NET_RAW`: For raw socket operations (nmap, ping)
- `NET_ADMIN`: For network administration tasks
- `NET_BIND_SERVICE`: For binding to privileged ports if needed

## License

This project is for educational purposes. Users are responsible for compliance with applicable laws and regulations.
