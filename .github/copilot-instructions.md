# Copilot Instructions for Kali MCP Pentest Server

## Project Overview
This repository contains a FastAPI-based MCP (Model Context Protocol) server running in a Kali Linux Docker container. It exposes security/penetration testing tools via HTTP API for educational purposes.

### Key Technologies
- **Python/FastAPI**: Web API framework
- **Docker**: Containerization with Kali Linux base
- **Security Tools**: nmap, nikto, sqlmap, wpscan, dirb, searchsploit
- **GitHub Actions**: CI/CD for Docker builds

## Development Guidelines

### Code Style & Security
- Always sanitize user inputs using the `sanitize_target()` function
- Use the `ALLOWED_TOOLS` list to whitelist executable tools
- Follow the existing pattern for adding new endpoints (POST with Form data)
- Implement proper error handling with meaningful HTTP status codes
- Keep subprocess calls with timeouts to prevent hanging

### API Endpoints
All endpoints follow this pattern:
```python
@app.post("/{tool}", response_class=PlainTextResponse)
def tool_scan(target: str = Form(...)):
    target = sanitize_target(target)
    return run_tool("tool", ["args", target])
```

### Testing & Validation
- Test API endpoints using curl or similar tools
- Validate input sanitization prevents command injection
- Ensure tools run with proper non-root permissions
- Test Docker container builds and runs correctly
- Verify GitHub Actions workflow builds successfully

### Security Considerations
- **Educational Use Only**: This tool is for learning purposes
- **Input Validation**: Always validate and sanitize inputs
- **Non-root Execution**: Container runs as `kaliuser`
- **Capability Management**: Minimal required Linux capabilities
- **Command Injection Prevention**: Block dangerous characters

### Docker Development
- Base image: `kalilinux/kali-rolling`
- Required capabilities: `NET_RAW`, `NET_ADMIN`, `NET_BIND_SERVICE`
- Exposed port: 8080
- Working directory: `/home/kaliuser/app`

### Build & Run Commands
```bash
# Build the Docker image
docker build -t kali-mcp-server .

# Run the container
docker run -p 8080:8080 --cap-add=NET_RAW --cap-add=NET_ADMIN --cap-add=NET_BIND_SERVICE kali-mcp-server

# Test API endpoints
curl -X POST -F "target=scanme.nmap.org" http://localhost:8080/nmap
```

### File Structure
- `main.py`: FastAPI application with tool endpoints
- `Dockerfile`: Container definition with Kali Linux and tools
- `requirements.txt`: Python dependencies
- `.github/workflows/docker-build.yml`: CI/CD pipeline
- `README.md`: User documentation

### Adding New Tools
1. Add tool name to `ALLOWED_TOOLS` list
2. Create new endpoint following existing pattern
3. Update README.md with new endpoint documentation
4. Test tool installation in Dockerfile if needed
5. Validate security and input sanitization

### Common Issues
- **Permission errors**: Ensure proper capabilities are set
- **Tool not found**: Verify installation in Dockerfile
- **Timeout errors**: Adjust timeout in `run_tool()` function
- **Input validation**: Use `sanitize_target()` for all user inputs
