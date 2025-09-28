import os
import subprocess
from mcp.server.fastmcp import FastMCP

# Initialize MCP Server
mcp = FastMCP(
    name="kali-mcp-pentest-server",
    instructions="A penetration testing MCP server providing access to common security tools like nmap, nikto, sqlmap, wpscan, dirb, and searchsploit.",
    host="0.0.0.0",
    port=8080
)

# Environment config
ALLOWED_TOOLS = ["nmap", "nikto", "sqlmap", "wpscan", "dirb", "searchsploit"]

# Input sanitization helper
def sanitize_target(target: str) -> str:
    if not target or any(c in target for c in ";&|$`\n\r"):
        raise ValueError("Invalid target: contains dangerous characters")
    return target.strip()

def run_tool(tool: str, args: list) -> str:
    if tool not in ALLOWED_TOOLS:
        raise ValueError(f"Tool not allowed: {tool}")
    cmd = [tool] + args
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        return result.stdout + "\n" + result.stderr
    except Exception as e:
        return f"Error running {tool}: {str(e)}"

@mcp.tool()
def nmap_scan(target: str) -> str:
    """
    Run nmap network scanner on a target.
    
    Args:
        target: The target hostname or IP address to scan
        
    Returns:
        String containing nmap scan results
    """
    target = sanitize_target(target)
    return run_tool("nmap", ["-Pn", target])

@mcp.tool()
def nikto_scan(target: str) -> str:
    """
    Run nikto web server scanner on a target.
    
    Args:
        target: The target hostname or IP address to scan
        
    Returns:
        String containing nikto scan results
    """
    target = sanitize_target(target)
    return run_tool("nikto", ["-h", target])

@mcp.tool()
def sqlmap_scan(target: str) -> str:
    """
    Run sqlmap SQL injection testing tool on a target URL.
    
    Args:
        target: The target URL to test for SQL injection
        
    Returns:
        String containing sqlmap scan results
    """
    target = sanitize_target(target)
    return run_tool("sqlmap", ["-u", target, "--batch"])

@mcp.tool()
def wpscan_scan(target: str) -> str:
    """
    Run wpscan WordPress security scanner on a target.
    
    Args:
        target: The target WordPress URL to scan
        
    Returns:
        String containing wpscan results
    """
    target = sanitize_target(target)
    return run_tool("wpscan", ["--url", target])

@mcp.tool()
def dirb_scan(target: str) -> str:
    """
    Run dirb directory/file brute force scanner on a target.
    
    Args:
        target: The target URL to scan for directories and files
        
    Returns:
        String containing dirb scan results
    """
    target = sanitize_target(target)
    return run_tool("dirb", [target])

@mcp.tool()
def searchsploit_query(query: str) -> str:
    """
    Search exploit database using searchsploit.
    
    Args:
        query: Search term to look for exploits
        
    Returns:
        String containing searchsploit results
    """
    query = sanitize_target(query)
    return run_tool("searchsploit", [query])

# Legacy HTTP endpoint compatibility (optional)
@mcp.custom_route("/", methods=["GET"])
async def root(request):
    from starlette.responses import JSONResponse
    return JSONResponse({"message": "Kali MCP Pentest Server running", "protocol": "MCP", "tools": len(ALLOWED_TOOLS)})

if __name__ == "__main__":
    # Run with streamable-http transport for web-based clients like N8N
    # This provides both SSE and HTTP endpoints for maximum compatibility
    mcp.run(transport="streamable-http")
