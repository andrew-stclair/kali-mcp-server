# Kali MCP Pentest Server

A FastAPI-based MCP server running in a Kali Linux Docker container, exposing security tools (nmap, nikto, sqlmap, wpscan, dirb, searchsploit) via HTTP API for educational pentesting.

## Features
- HTTP API (port 8080) for each tool
- Input sanitization
- Non-root execution with required capabilities
- Python virtual environment for dependency isolation
- Dockerfile for reproducible builds
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

### API Endpoints
Access the API endpoints (POST requests):
- `/nmap` (target)
- `/nikto` (target)
- `/sqlmap` (target)
- `/wpscan` (target)
- `/dirb` (target)
- `/searchsploit` (query)

### Example Usage
Test the API endpoints using curl:
```bash
# Test nmap scan
curl -X POST -F "target=scanme.nmap.org" http://localhost:8080/nmap

# Test searchsploit query
curl -X POST -F "query=apache" http://localhost:8080/searchsploit

# Check service status
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
