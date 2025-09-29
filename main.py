import os
import subprocess
from mcp.server.fastmcp import FastMCP

# Initialize MCP Server
mcp = FastMCP(
    name="kali-mcp-pentest-server",
    instructions="A penetration testing MCP server providing access to common security tools like nmap, nikto, sqlmap, wpscan, dirb, gobuster, searchsploit, sherlock, ping, and traceroute.",
    host="0.0.0.0",
    port=8080
)

# Environment config
ALLOWED_TOOLS = ["nmap", "nikto", "sqlmap", "wpscan", "dirb", "searchsploit", "ping", "traceroute", "gobuster", "sherlock"]

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

@mcp.tool()
def ping_scan(target: str) -> str:
    """
    Run ping network connectivity test on a target.
    
    Args:
        target: The target hostname or IP address to ping
        
    Returns:
        String containing ping results
    """
    target = sanitize_target(target)
    return run_tool("ping", ["-c", "4", target])

@mcp.tool()
def traceroute_scan(target: str) -> str:
    """
    Run traceroute network path trace to a target.
    
    Args:
        target: The target hostname or IP address to trace route to
        
    Returns:
        String containing traceroute results
    """
    target = sanitize_target(target)
    return run_tool("traceroute", [target])

@mcp.tool()
def gobuster_dir_scan(target: str) -> str:
    """
    Run gobuster directory/file brute force scanner on a target URL.
    
    Args:
        target: The target URL to scan for directories and files
        
    Returns:
        String containing gobuster directory scan results
    """
    target = sanitize_target(target)
    return run_tool("gobuster", ["dir", "-u", target, "-w", "/usr/share/seclists/Discovery/Web-Content/common.txt"])

@mcp.tool()
def gobuster_dns_scan(target: str) -> str:
    """
    Run gobuster DNS subdomain brute force scanner on a target domain.
    
    Args:
        target: The target domain to scan for subdomains
        
    Returns:
        String containing gobuster DNS scan results
    """
    target = sanitize_target(target)
    return run_tool("gobuster", ["dns", "-d", target, "-w", "/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt"])

@mcp.tool()
def gobuster_vhost_scan(target: str) -> str:
    """
    Run gobuster virtual host brute force scanner on a target URL.
    
    Args:
        target: The target URL to scan for virtual hosts
        
    Returns:
        String containing gobuster vhost scan results
    """
    target = sanitize_target(target)
    return run_tool("gobuster", ["vhost", "-u", target, "-w", "/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt"])

@mcp.tool()
def sherlock_scan(username: str) -> str:
    """
    Run sherlock username reconnaissance tool to find social media accounts.
    
    Args:
        username: The username to search for across social networks
        
    Returns:
        String containing sherlock scan results with found social media profiles
    """
    username = sanitize_target(username)
    return run_tool("sherlock", ["--timeout", "30", "--print-found", "--no-color", username])

# Legacy HTTP endpoint compatibility (optional)
@mcp.custom_route("/", methods=["GET"])
async def root(request):
    from starlette.responses import JSONResponse
    return JSONResponse({"message": "Kali MCP Pentest Server running", "protocol": "MCP", "tools": len(ALLOWED_TOOLS)})

if __name__ == "__main__":
    # Run with streamable-http transport for web-based clients like N8N
    # This provides both SSE and HTTP endpoints for maximum compatibility
    mcp.run(transport="streamable-http")
