# Kali MCP Pentest Server

A comprehensive Model Context Protocol (MCP) server that provides access to 22 essential penetration testing tools through a standardized interface. Built on Kali Linux and designed for integration with AI assistants and automation platforms.

## Overview

This project packages essential security testing tools into an MCP server running in a containerized Kali Linux environment. It uses the FastMCP framework to expose security tools with proper input validation, timeout handling, and safety controls. Each tool is optimized for LLM integration with detailed output analysis capabilities.

## Available Tools

The server provides 22 comprehensive security testing tools via MCP, organized by category:

### Network Discovery & Scanning
| Tool | Purpose | Input Type | Key Outputs for LLM Analysis |
|------|---------|------------|------------------------------|
| `nmap_scan` | Network port scanning and host discovery | hostname/IP/range + optional ports | Open ports, service versions, OS detection for further targeting. Scans 10 common ports by default (21,22,23,25,80,443,3306,3389,5432,8080). Use `ports` parameter to scan custom ports or ranges (e.g., "80,443" or "1-1000"). |
| `ping_scan` | ICMP connectivity testing | hostname/IP | IP resolution, latency, availability for follow-up scans |
| `traceroute_scan` | Network path tracing | hostname/IP | Router IPs, network topology for infrastructure mapping |
| `arping_scan` | Layer 2 ARP host discovery | local IP | MAC addresses, vendor info for local network mapping |

### Advanced Network Testing
| Tool | Purpose | Input Type | Key Outputs for LLM Analysis |
|------|---------|------------|------------------------------|
| `hping3_ping_scan` | TCP connectivity through firewalls | hostname/IP | Firewall bypass, advanced connectivity testing |
| `hping3_port_scan` | Stealthy TCP port scanning | hostname/IP | Stealth scanning results, security device detection |
| `hping3_traceroute_scan` | TCP-based network path tracing | hostname/IP | Firewall-aware routing, network security analysis |

### DNS & Infrastructure Analysis
| Tool | Purpose | Input Type | Key Outputs for LLM Analysis |
|------|---------|------------|------------------------------|
| `dns_lookup` | Comprehensive DNS record enumeration | domain name | A/AAAA/MX/NS/TXT/SRV records for infrastructure mapping |
| `gobuster_dns_scan` | High-speed subdomain enumeration | domain name | Hidden subdomains, additional attack surfaces |
| `geoip_lookup` | IP geolocation and ISP analysis | IPv4/IPv6 address | Geographic location, ISP info, network ownership |

### Web Application Security
| Tool | Purpose | Input Type | Key Outputs for LLM Analysis |
|------|---------|------------|------------------------------|
| `nikto_scan` | Web server vulnerability scanning | URL/hostname | Vulnerabilities, misconfigurations, attack vectors |
| `sqlmap_scan` | Automated SQL injection testing | URL with parameters | Database vulnerabilities, injection points |
| `wpscan_scan` | WordPress security assessment | WordPress URL | Plugin/theme vulnerabilities, user enumeration |
| `dirb_scan` | Directory/file brute force discovery | URL | Hidden directories, admin panels, sensitive files |
| `gobuster_dir_scan` | High-speed directory enumeration | URL | Fast directory discovery, backup files |
| `gobuster_vhost_scan` | Virtual host discovery | URL/IP | Hidden vhosts, shared hosting enumeration |

### Web Content Analysis
| Tool | Purpose | Input Type | Key Outputs for LLM Analysis |
|------|---------|------------|------------------------------|
| `whatweb_scan` | Web technology fingerprinting | URL | CMS detection, framework identification, versions |
| `photon_scan` | Intelligent web crawling & OSINT | URL | URLs, emails, API endpoints, social media links |
| `lynx_extract_links` | Comprehensive link extraction | URL | All hyperlinks, forms, resources for further testing |
| `lynx_get_content` | Clean text content for LLM analysis | URL | Formatted page content, forms, error messages |

### Intelligence & Research Tools
| Tool | Purpose | Input Type | Key Outputs for LLM Analysis |
|------|---------|------------|------------------------------|
| `searchsploit_query` | Exploit database search | software/version/CVE | Available exploits, PoCs, security advisories |
| `sherlock_scan` | Username reconnaissance | username | Social media profiles, digital footprint mapping |

## LLM Integration & Tool Chaining

### Intelligent Tool Sequencing
The tools are designed for intelligent chaining and LLM-driven analysis:

1. **Discovery Phase**: `ping_scan` → `nmap_scan` → `dns_lookup` → `geoip_lookup`
2. **Web Analysis**: `whatweb_scan` → `nikto_scan` → `dirb_scan` → `gobuster_dir_scan`
3. **Content Analysis**: `lynx_extract_links` → `lynx_get_content` → `sqlmap_scan`
4. **Intelligence Gathering**: `photon_scan` → `sherlock_scan` → `searchsploit_query`

### Cross-Tool Data Flow Examples

- **IP Discovery**: Extract IPs from `nmap_scan` → feed to `geoip_lookup`
- **Subdomain Enumeration**: Get subdomains from `gobuster_dns_scan` → test each with `whatweb_scan`
- **Vulnerability Research**: Find services in `nmap_scan` → search versions with `searchsploit_query`
- **Social Engineering**: Discover usernames → use `sherlock_scan` → analyze profiles with `lynx_get_content`

### LLM Analysis Capabilities

Each tool provides structured output optimized for:
- **Pattern Recognition**: Identifying attack vectors and vulnerabilities
- **Data Extraction**: Parsing IPs, URLs, versions, and credentials
- **Risk Assessment**: Prioritizing findings based on severity and exploitability
- **Report Generation**: Creating comprehensive security assessments
- **Automated Decision Making**: Determining next steps in reconnaissance

## Architecture

- **Base**: Kali Linux (`kalilinux/kali-rolling`) Docker container with 22 security tools
- **Framework**: FastMCP for MCP protocol implementation with LLM-optimized interfaces  
- **Transport**: StreamableHTTP (supports SSE and HTTP endpoints for maximum compatibility)
- **Security**: Non-root execution with minimal required capabilities (`NET_RAW`, `NET_ADMIN`, `NET_BIND_SERVICE`)
- **Dependencies**: Python virtual environment with comprehensive security tool integration
- **Input Validation**: Advanced sanitization for IP addresses, URLs, and general targets
- **Tool Safety**: Whitelisted tool execution with timeout controls and error handling

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
  --read-only \
  --tmpfs /tmp \
  --tmpfs /var/tmp \
  kali-mcp-server
```

### Using Pre-built Image

```bash
# Pull and run the latest image from GitHub Container Registry
docker run -p 8080:8080 \
  --cap-add=NET_RAW \
  --cap-add=NET_ADMIN \
  --cap-add=NET_BIND_SERVICE \
  --read-only \
  --tmpfs /tmp \
  --tmpfs /var/tmp \
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

- **Unit Tests** (`tests/test_utils.py`): Test core utility functions including IP address validation, input sanitization, and tool execution
- **MCP Tool Tests** (`tests/test_mcp_tools.py`): Test all 22 MCP tool functions with comprehensive mock execution and validation
- **Server Integration Tests** (`tests/test_mcp_server.py`): Test MCP server initialization and configuration
- **End-to-End Integration Tests** (`tests/test_integration.py`): Test complete workflows and error handling

#### Test Coverage

- Maintains **97%+ code coverage** with a minimum threshold of 85%
- Tests all 22 security tools exposed via MCP protocol
- Validates both general input sanitization and IP-specific validation
- Tests error handling for timeouts, permissions, and missing tools
- Ensures tool whitelisting security controls and capability requirements
- Comprehensive IPv4 and IPv6 address validation testing

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

### Security Hardening

- **Read-Only Filesystem**: Container runs with `--read-only` flag to prevent filesystem modifications
- **Temporary Filesystems**: Uses tmpfs mounts for `/tmp` and `/var/tmp` for necessary temporary operations
- **Non-Root Execution**: All tools run as unprivileged `kaliuser` account
- **Minimal Capabilities**: Only essential network capabilities are granted

### Capabilities Required

The container needs these Linux capabilities:
- `NET_RAW`: For raw socket operations (nmap, ping)
- `NET_ADMIN`: For network administration tasks
- `NET_BIND_SERVICE`: For binding to privileged ports if needed

## License

This project is for educational purposes. Users are responsible for compliance with applicable laws and regulations.
