# Kali MCP Pentest Server

A Model Context Protocol (MCP) server running in a Kali Linux Docker container, exposing security tools (nmap, nikto, sqlmap, wpscan, dirb, searchsploit) via MCP for integration with AI assistants and automation platforms like N8N.

## Features
- **MCP Protocol Support** - Compatible with N8N and other MCP clients  
- **6 Security Tools** as MCP tools with proper schemas
- **Input sanitization** to prevent command injection
- **Non-root execution** with required capabilities
- **Python virtual environment** for dependency isolation
- **Docker containerization** for reproducible builds
- **Multiple transport protocols** (SSE, HTTP, stdio)
- **Backward compatibility** with HTTP API endpoints
- GitHub Actions workflow for CI/CD

## Usage

### Using Docker Compose (Recommended)
1. Start the service:
   ```bash
   docker compose up -d
   ```
2. View logs:
   ```bash
   docker compose logs -f
   ```
3. Stop the service:
   ```bash
   docker compose down
   ```

### Using Docker (Manual)
1. Build the Docker image:
   ```bash
   docker build -t kali-mcp-server .
   ```
2. Run the container:
   ```bash
   docker run -p 8080:8080 --cap-add=NET_RAW --cap-add=NET_ADMIN --cap-add=NET_BIND_SERVICE kali-mcp-server
   ```

## MCP (Model Context Protocol) Usage

This server implements the MCP protocol for integration with AI assistants and automation platforms.

### MCP Client Integration (N8N)

1. **Server URL**: `http://localhost:8080/mcp`
2. **Transport**: HTTP with Server-Sent Events (SSE)
3. **Protocol**: JSON-RPC 2.0 over HTTP

#### N8N Configuration
```json
{
  "serverUrl": "http://localhost:8080",
  "transport": "http",
  "mcpPath": "/mcp"
}
```

**Important**: N8N will handle the MCP session management automatically. The server is configured with:
- **SSE endpoint**: `http://localhost:8080/sse` 
- **HTTP endpoint**: `http://localhost:8080/mcp`
- **Session management**: Automatic via StreamableHTTP transport

### Available MCP Tools

| Tool Name | Description | Parameter |
|-----------|-------------|-----------|
| `nmap_scan` | Network port scanner | `target` (string) |
| `nikto_scan` | Web server vulnerability scanner | `target` (string) |
| `sqlmap_scan` | SQL injection testing tool | `target` (string) |
| `wpscan_scan` | WordPress security scanner | `target` (string) |
| `dirb_scan` | Directory/file brute force scanner | `target` (string) |
| `searchsploit_query` | Exploit database search | `query` (string) |

### MCP Client Testing

The MCP protocol requires session management. For direct testing, you can:

1. **Connect to SSE endpoint** to get session information:
```bash
curl -H "Accept: text/event-stream" http://localhost:8080/sse
```

2. **Use MCP-compatible client libraries** like the official MCP Python client
3. **Use N8N's MCP tool node** which handles the protocol automatically

### Manual MCP Testing (Advanced)

```python
# This requires implementing MCP session management
# Recommended to use official MCP client libraries instead
```

## Legacy HTTP API Endpoints

For backward compatibility, the server still supports direct HTTP API access:
Access the legacy HTTP API endpoints (POST requests):
- `/nmap` (target)
- `/nikto` (target)
- `/sqlmap` (target)
- `/wpscan` (target)
- `/dirb` (target)
- `/searchsploit` (query)

### Example Usage
Test the legacy HTTP API endpoints using curl:
```bash
# Test nmap scan (legacy HTTP API)
curl -X POST -F "target=scanme.nmap.org" http://localhost:8080/nmap

# Test searchsploit query (legacy HTTP API)
curl -X POST -F "query=apache" http://localhost:8080/searchsploit

# Check service status (works with both MCP and HTTP)
curl http://localhost:8080/
```

## GitHub Actions
- Workflow in `.github/workflows/docker-build.yml` builds the Docker image on pull requests and pushes to GitHub Container Registry only on merge to `main`.
- Uses GitHub token authentication for container registry access.

## Security
- Runs as non-root user
- Input sanitization to prevent command injection
- Uses Python virtual environment to comply with PEP 668 (externally managed environment)
- For educational use only
