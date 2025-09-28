# Kali MCP Pentest Server

A FastAPI-based MCP server running in a Kali Linux Docker container, exposing security tools (nmap, nikto, sqlmap, wpscan, dirb, searchsploit) via HTTP API for educational pentesting.

## Features
- HTTP API (port 8080) for each tool
- Input sanitization
- Non-root execution with required capabilities
- Dockerfile for reproducible builds
- GitHub Actions workflow for CI/CD

## Usage
1. Build the Docker image:
   ```bash
   docker build -t kali-mcp-server .
   ```
2. Run the container:
   ```bash
   docker run -p 8080:8080 --cap-add=NET_RAW --cap-add=NET_ADMIN --cap-add=NET_BIND_SERVICE kali-mcp-server
   ```
3. Access the API endpoints (POST requests):
   - `/nmap` (target)
   - `/nikto` (target)
   - `/sqlmap` (target)
   - `/wpscan` (target)
   - `/dirb` (target)
   - `/searchsploit` (query)

## GitHub Actions
- Workflow in `.github/workflows/docker-build.yml` builds and pushes the Docker image to DockerHub on push to `main`.
- Set `DOCKERHUB_USERNAME` and `DOCKERHUB_TOKEN` secrets in your repository.

## Security
- Runs as non-root user
- Input sanitization to prevent command injection
- For educational use only
