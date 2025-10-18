import os
import subprocess
import ipaddress
from mcp.server.fastmcp import FastMCP

# Initialize MCP Server
mcp = FastMCP(
    name="kali-mcp-pentest-server",
    instructions="A penetration testing MCP server providing access to common security tools like nmap, nikto, sqlmap, wpscan, dirb, gobuster, searchsploit, sherlock, whatweb, ping, traceroute, dns lookup, geolocation lookup, hping3, arping, photon, and lynx for web content analysis.",
    host="0.0.0.0",
    port=8080
)

# Environment config
ALLOWED_TOOLS = ["nmap", "nikto", "sqlmap", "wpscan", "dirb", "searchsploit", "ping", "traceroute", "gobuster", "sherlock", "whatweb", "hping3", "arping", "photon", "lynx", "dig", "geoiplookup"]

# Input sanitization helper
def sanitize_target(target: str) -> str:
    if target is None or not isinstance(target, str):
        raise ValueError("Invalid target: contains dangerous characters")
    target = target.strip()
    if not target or any(c in target for c in ";&|$`\n\r"):
        raise ValueError("Invalid target: contains dangerous characters")
    return target

def sanitize_ip_address(ip: str) -> str:
    """Sanitize and validate IP address (IPv4 or IPv6)."""
    if ip is None or not isinstance(ip, str):
        raise ValueError("Invalid IP address: must be a string")
    ip = ip.strip()
    if not ip:
        raise ValueError("Invalid IP address: empty string")
    
    try:
        # This will raise ValueError if not a valid IP address
        ipaddress.ip_address(ip)
        return ip
    except ValueError:
        raise ValueError("Invalid IP address: not a valid IPv4 or IPv6 address")

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
def dns_lookup(target: str) -> str:
    """
    Perform comprehensive DNS lookup for all record types including A, AAAA, MX, NS, TXT, SOA, SRV, etc.
    
    Args:
        target: The domain name to perform DNS lookup on
        
    Returns:
        String containing comprehensive DNS lookup results for all record types
    """
    target = sanitize_target(target)
    return run_tool("dig", ["ANY", target, "+noall", "+answer", "+additional"])

@mcp.tool()
def geoip_lookup(ip_address: str) -> str:
    """
    Perform geolocation lookup for an IP address (IPv4 or IPv6) to get location information.
    
    Args:
        ip_address: The IPv4 or IPv6 address to perform geolocation lookup on
        
    Returns:
        String containing geolocation information including country, region, city, ISP, etc.
    """
    ip_address = sanitize_ip_address(ip_address)
    return run_tool("geoiplookup", [ip_address])

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

    This tool returns a list of URL's, It is worth getting the content of these pages
    separately to extract more useful information.
    
    Args:
        username: The username to search for across social networks
        
    Returns:
        String containing sherlock scan results with url's of found social media profiles
    """
    username = sanitize_target(username)
    return run_tool("sherlock", ["--timeout", "3", "--print-found", "--no-color", username])

@mcp.tool()
def whatweb_scan(target: str) -> str:
    """
    Run whatweb web technology scanner on a target URL.
    
    Args:
        target: The target URL to scan for web technologies
        
    Returns:
        String containing whatweb scan results identifying web technologies
    """
    target = sanitize_target(target)
    return run_tool("whatweb", ["--no-color", target])

@mcp.tool()
def hping3_ping_scan(target: str) -> str:
    """
    Run hping3 TCP ping test on a target for connectivity testing.
    
    Args:
        target: The target hostname or IP address to ping
        
    Returns:
        String containing hping3 TCP ping results for connectivity analysis
    """
    target = sanitize_target(target)
    return run_tool("hping3", ["-c", "4", "-S", "-p", "80", target])

@mcp.tool()
def hping3_port_scan(target: str) -> str:
    """
    Run hping3 SYN port scan on common ports for reconnaissance.
    
    Args:
        target: The target hostname or IP address to scan
        
    Returns:
        String containing hping3 port scan results showing open/closed ports
    """
    target = sanitize_target(target)
    return run_tool("hping3", ["-c", "1", "-S", "-p", "80", target])

@mcp.tool()
def hping3_traceroute_scan(target: str) -> str:
    """
    Run hping3 TCP traceroute to trace network path to target.
    
    Args:
        target: The target hostname or IP address to trace route to
        
    Returns:
        String containing hping3 traceroute results showing network path
    """
    target = sanitize_target(target)
    return run_tool("hping3", ["--traceroute", "-c", "3", "-S", "-p", "80", target])

@mcp.tool()
def arping_scan(target: str) -> str:
    """
    Run arping ARP ping test on a target for Layer 2 connectivity testing.
    
    Args:
        target: The target hostname or IP address to ARP ping
        
    Returns:
        String containing arping results for Layer 2 connectivity analysis
    """
    target = sanitize_target(target)
    return run_tool("arping", ["-c", "4", target])

@mcp.tool()
def photon_scan(target: str) -> str:
    """
    Run photon web crawler for OSINT and reconnaissance.
    
    Args:
        target: The target URL to crawl and analyze
        
    Returns:
        String containing photon scan results with discovered URLs and intelligence
    """
    target = sanitize_target(target)
    return run_tool("photon", ["-u", target, "-l", "2", "--only-urls", "--timeout", "30"])

@mcp.tool()
def lynx_extract_links(target: str) -> str:
    """
    Extract all links from a web page using lynx browser.
    
    Args:
        target: The target URL to extract links from
        
    Returns:
        String containing all links found on the page
    """
    target = sanitize_target(target)
    return run_tool("lynx", ["-dump", "-listonly", target])

@mcp.tool()
def lynx_get_content(target: str) -> str:
    """
    Get web page content formatted for LLM context using lynx browser.
    
    Args:
        target: The target URL to retrieve content from
        
    Returns:
        String containing formatted text content of the web page
    """
    target = sanitize_target(target)
    return run_tool("lynx", ["-dump", "-nolist", "-width=120", target])

# Legacy HTTP endpoint compatibility (optional)
@mcp.custom_route("/", methods=["GET"])
async def root(request):
    from starlette.responses import JSONResponse
    return JSONResponse({"message": "Kali MCP Pentest Server running", "protocol": "MCP", "tools": len(ALLOWED_TOOLS)})

if __name__ == "__main__":
    # Run with streamable-http transport for web-based clients like N8N
    # This provides both SSE and HTTP endpoints for maximum compatibility
    mcp.run(transport="streamable-http")
