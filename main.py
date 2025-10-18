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
    Perform network port scanning and host discovery using Nmap.
    
    This tool performs a basic Nmap scan with host discovery disabled (-Pn) to enumerate 
    open ports, running services, and basic host information. Essential for network reconnaissance.
    
    Args:
        target: The target hostname, IP address, or IP range (e.g., "example.com", "192.168.1.1", "192.168.1.0/24")
        
    Returns:
        String containing detailed scan results including:
        - Open ports and their associated services
        - Service versions and banners (when detectable)
        - Host status and response times
        - MAC addresses (for local network targets)
        
    LLM Usage Tips:
        - Extract open ports for further investigation with specific service scanners
        - Use discovered services as input for vulnerability scanning (nikto_scan, sqlmap_scan)
        - Parse service versions to search for exploits using searchsploit_query
        - Combine with dns_lookup for comprehensive host profiling
        - Use IP addresses from results with geoip_lookup for location analysis
    """
    target = sanitize_target(target)
    return run_tool("nmap", ["-Pn", target])

@mcp.tool()
def nikto_scan(target: str) -> str:
    """
    Perform comprehensive web server vulnerability scanning using Nikto.
    
    Scans web servers for known vulnerabilities, misconfigurations, dangerous files, 
    outdated server software, and security issues. Essential for web application security assessment.
    
    Args:
        target: Target web server (hostname, IP, or full URL like "http://example.com" or "https://192.168.1.1")
        
    Returns:
        String containing vulnerability scan results including:
        - Server information and version detection
        - Identified vulnerabilities with severity ratings
        - Suspicious files and directories found
        - Configuration issues and security headers
        - CGI vulnerabilities and potential attack vectors
        
    LLM Usage Tips:
        - Use URLs from lynx_extract_links output as targets for deeper scanning
        - Extract vulnerable paths/files for manual verification with lynx_get_content
        - Combine findings with searchsploit_query to find specific exploits
        - Use server version info for targeted vulnerability research
        - Cross-reference findings with dirb_scan results for comprehensive coverage
    """
    target = sanitize_target(target)
    return run_tool("nikto", ["-h", target])

@mcp.tool()
def sqlmap_scan(target: str) -> str:
    """
    Perform automated SQL injection testing and database exploitation using SQLMap.
    
    Tests web applications for SQL injection vulnerabilities and can extract database 
    information if vulnerabilities are found. Runs in batch mode for automated testing.
    
    Args:
        target: Target URL with parameters (e.g., "http://example.com/page.php?id=1" or "http://site.com/login")
        
    Returns:
        String containing SQL injection test results including:
        - Vulnerability detection and injection points
        - Database type, version, and backend information
        - Available databases, tables, and columns (if exploitable)
        - Extracted data samples and system information
        - Recommended exploitation techniques and payloads
        
    LLM Usage Tips:
        - Use URLs with parameters from lynx_extract_links or dirb_scan results
        - Target forms and login pages discovered during reconnaissance
        - Combine with web content analysis from lynx_get_content to identify input fields
        - Use database information for further exploitation planning
        - Cross-reference findings with searchsploit_query for database-specific exploits
    """
    target = sanitize_target(target)
    return run_tool("sqlmap", ["-u", target, "--batch"])

@mcp.tool()
def wpscan_scan(target: str) -> str:
    """
    Perform comprehensive WordPress security scanning and enumeration using WPScan.
    
    Specifically targets WordPress installations to identify vulnerabilities, plugins, 
    themes, users, and configuration issues. Essential for WordPress security assessment.
    
    Args:
        target: Target WordPress URL (e.g., "http://example.com" or "https://blog.site.com")
        
    Returns:
        String containing WordPress security scan results including:
        - WordPress version detection and known vulnerabilities
        - Installed plugins and themes with version information
        - Enumerated users and potential attack vectors
        - Configuration files and sensitive information disclosure
        - Security headers and hardening recommendations
        
    LLM Usage Tips:
        - Use WordPress URLs discovered from whatweb_scan or dirb_scan results
        - Extract plugin/theme names and versions for searchsploit_query vulnerability research
        - Target enumerated usernames with password attacks or social engineering
        - Combine findings with nikto_scan for comprehensive web security assessment
        - Use version information to research specific WordPress CVEs and exploits
    """
    target = sanitize_target(target)
    return run_tool("wpscan", ["--url", target])

@mcp.tool()
def dirb_scan(target: str) -> str:
    """
    Perform web directory and file brute force discovery using DIRB.
    
    Discovers hidden directories, files, and resources on web servers using dictionary 
    attacks. Essential for finding administrative interfaces, backup files, and sensitive content.
    
    Args:
        target: Target web server URL (e.g., "http://example.com" or "https://192.168.1.1")
        
    Returns:
        String containing directory brute force results including:
        - Discovered directories and their HTTP response codes
        - Found files and their accessibility status
        - Hidden administrative panels and interfaces
        - Backup files and sensitive documents
        - Response size analysis for content validation
        
    LLM Usage Tips:
        - Use discovered directories as targets for deeper nikto_scan analysis
        - Examine found files with lynx_get_content for sensitive information
        - Target admin panels and login forms with sqlmap_scan for injection testing
        - Combine results with gobuster scans for comprehensive enumeration
        - Use backup files and configs to extract credentials or system information
    """
    target = sanitize_target(target)
    return run_tool("dirb", [target])

@mcp.tool()
def searchsploit_query(query: str) -> str:
    """
    Search the Exploit Database for known exploits and proof-of-concept code.
    
    Queries the comprehensive Exploit-DB database to find available exploits, 
    shellcode, and security papers for specific software, versions, or vulnerabilities.
    
    Args:
        query: Search terms (e.g., "apache 2.4", "wordpress 5.8", "CVE-2021-44228", "linux kernel")
        
    Returns:
        String containing exploit database search results including:
        - Available exploits with EDB-ID numbers
        - Exploit titles and descriptions
        - Target platforms and software versions
        - Exploit types (remote, local, DoS, etc.)
        - File paths for accessing exploit code
        
    LLM Usage Tips:
        - Use software versions from nmap_scan, nikto_scan, or whatweb_scan results
        - Query specific CVEs discovered during vulnerability scans
        - Search for exploits matching discovered services and applications
        - Combine with version information from wpscan_scan for WordPress exploits
        - Use product names and versions from any reconnaissance output
        - Research exploits for operating systems identified during scanning
    """
    query = sanitize_target(query)
    return run_tool("searchsploit", [query])

@mcp.tool()
def ping_scan(target: str) -> str:
    """
    Perform ICMP connectivity testing and basic network reachability analysis.
    
    Tests network connectivity using ICMP echo requests to determine if a host 
    is reachable and measure response times. Fundamental network diagnostic tool.
    
    Args:
        target: Target hostname or IP address (e.g., "google.com", "192.168.1.1")
        
    Returns:
        String containing ping connectivity results including:
        - Response times and packet loss statistics
        - IP address resolution for hostnames
        - Network latency and jitter measurements
        - Host reachability status and availability
        - Network route responsiveness indicators
        
    LLM Usage Tips:
        - Use resolved IP addresses with geoip_lookup for location information
        - Test connectivity before running other network scans (nmap_scan)
        - Verify host availability for web-based tools (nikto_scan, dirb_scan)
        - Extract IP addresses for further network reconnaissance
        - Use timing information to assess network conditions and filtering
    """
    target = sanitize_target(target)
    return run_tool("ping", ["-c", "4", target])

@mcp.tool()
def traceroute_scan(target: str) -> str:
    """
    Trace network routing path and analyze network topology to target destination.
    
    Maps the network path packets take to reach a destination, revealing intermediate 
    routers and network infrastructure. Essential for network reconnaissance and troubleshooting.
    
    Args:
        target: Target hostname or IP address (e.g., "example.com", "8.8.8.8")
        
    Returns:
        String containing network path trace results including:
        - Hop-by-hop router IP addresses and hostnames
        - Response times for each network segment
        - Network topology and routing infrastructure
        - Potential network bottlenecks and filtering points
        - Geographic distribution of network infrastructure
        
    LLM Usage Tips:
        - Extract router IP addresses for geoip_lookup location analysis
        - Identify potential network choke points and security devices
        - Use intermediate hostnames for dns_lookup reverse resolution
        - Analyze routing patterns for network mapping and reconnaissance
        - Combine with ping_scan results for comprehensive network analysis
    """
    target = sanitize_target(target)
    return run_tool("traceroute", [target])

@mcp.tool()
def dns_lookup(target: str) -> str:
    """
    Perform comprehensive DNS enumeration and record analysis for domain intelligence.
    
    Retrieves all available DNS record types to gather maximum information about 
    domain infrastructure, mail servers, subdomains, and network configuration.
    
    Args:
        target: Domain name to analyze (e.g., "example.com", "subdomain.site.org")
        
    Returns:
        String containing comprehensive DNS analysis results including:
        - A records (IPv4 addresses) and AAAA records (IPv6 addresses)
        - MX records (mail servers) and their priorities
        - NS records (name servers) and SOA (start of authority)
        - TXT records (SPF, DKIM, verification codes, policies)
        - CNAME records (aliases) and SRV records (services)
        - Additional section with related IP addresses
        
    LLM Usage Tips:
        - Use extracted IP addresses with geoip_lookup for geographic analysis
        - Target mail servers (MX records) with nmap_scan for service enumeration
        - Analyze TXT records for security policies and third-party integrations
        - Use name server IPs for infrastructure reconnaissance
        - Extract subdomains from CNAME records for further testing
        - Target discovered IPs with network scanning and web analysis tools
    """
    target = sanitize_target(target)
    return run_tool("dig", ["ANY", target, "+noall", "+answer", "+additional"])

@mcp.tool()
def geoip_lookup(ip_address: str) -> str:
    """
    Perform geolocation and ISP analysis for IP addresses using GeoIP databases.
    
    Analyzes IP addresses to determine geographic location, network ownership, 
    and organizational information. Essential for threat intelligence and network analysis.
    
    Args:
        ip_address: Valid IPv4 or IPv6 address (e.g., "8.8.8.8", "2001:4860:4860::8888")
        
    Returns:
        String containing comprehensive geolocation data including:
        - Country, region/state, and city location information
        - Internet Service Provider (ISP) and organization details
        - Autonomous System Number (ASN) and network operator
        - Timezone and coordinates (when available)
        - Network type classification (residential, hosting, mobile, etc.)
        
    LLM Usage Tips:
        - Use IP addresses extracted from nmap_scan, ping_scan, or dns_lookup results
        - Analyze server locations from traceroute_scan intermediate hops
        - Combine with network reconnaissance for infrastructure mapping
        - Identify hosting providers and cloud service locations
        - Assess geographic distribution of network infrastructure
        - Use for threat attribution and network ownership analysis
    """
    ip_address = sanitize_ip_address(ip_address)
    return run_tool("geoiplookup", [ip_address])

@mcp.tool()
def gobuster_dir_scan(target: str) -> str:
    """
    Perform high-speed directory and file brute force discovery using Gobuster.
    
    Fast, multi-threaded web directory enumeration using common wordlists. 
    More efficient than DIRB for large-scale directory discovery and enumeration.
    
    Args:
        target: Target web server URL (e.g., "http://example.com", "https://192.168.1.1:8080")
        
    Returns:
        String containing directory brute force results including:
        - Discovered directories and files with HTTP status codes
        - Response sizes for content analysis and validation
        - Hidden administrative interfaces and backup files
        - Potential upload directories and user content areas
        - High-speed enumeration results with detailed paths
        
    LLM Usage Tips:
        - Complement dirb_scan results with faster, more comprehensive enumeration
        - Use discovered paths for nikto_scan vulnerability analysis
        - Target found directories with lynx_get_content for manual inspection
        - Extract admin panels and forms for sqlmap_scan injection testing
        - Combine with whatweb_scan results for technology-specific directory patterns
    """
    target = sanitize_target(target)
    return run_tool("gobuster", ["dir", "-u", target, "-w", "/usr/share/seclists/Discovery/Web-Content/common.txt"])

@mcp.tool()
def gobuster_dns_scan(target: str) -> str:
    """
    Perform high-speed subdomain enumeration and DNS brute force using Gobuster.
    
    Fast discovery of subdomains using comprehensive wordlists to identify 
    additional attack surfaces and infrastructure components not found via DNS zone transfers.
    
    Args:
        target: Target domain name (e.g., "example.com", "target-company.org")
        
    Returns:
        String containing subdomain discovery results including:
        - Found subdomains and their resolved IP addresses
        - Hidden development, staging, and administrative interfaces
        - Third-party service integrations and cloud resources
        - Regional or departmental subdomain patterns
        - Potential attack surface expansion opportunities
        
    LLM Usage Tips:
        - Use discovered subdomains as targets for individual nmap_scan analysis
        - Test found subdomains with web scanning tools (nikto_scan, dirb_scan)
        - Extract IP addresses from results for geoip_lookup analysis
        - Target subdomains for technology profiling with whatweb_scan
        - Use subdomain patterns to generate additional targeted wordlists
    """
    target = sanitize_target(target)
    return run_tool("gobuster", ["dns", "-d", target, "-w", "/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt"])

@mcp.tool()
def gobuster_vhost_scan(target: str) -> str:
    """
    Discover virtual hosts and name-based virtual hosting configurations using Gobuster.
    
    Identifies virtual hosts hosted on the same IP address through HTTP Host header 
    manipulation, revealing additional web applications and services not found through DNS.
    
    Args:
        target: Target web server URL (e.g., "http://192.168.1.1", "https://example.com")
        
    Returns:
        String containing virtual host discovery results including:
        - Found virtual hostnames and their response characteristics
        - Hidden web applications sharing the same IP address
        - Name-based virtual hosting configurations and patterns
        - Additional attack surfaces on shared hosting infrastructure
        - Response size differences indicating valid virtual hosts
        
    LLM Usage Tips:
        - Use IP addresses from nmap_scan or dns_lookup results as targets
        - Test discovered virtual hosts with web scanning tools individually
        - Combine results with gobuster_dns_scan for comprehensive enumeration
        - Target found vhosts with nikto_scan and dirb_scan for vulnerability analysis
        - Use virtual host patterns for additional targeted discovery
    """
    target = sanitize_target(target)
    return run_tool("gobuster", ["vhost", "-u", target, "-w", "/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt"])

@mcp.tool()
def sherlock_scan(username: str) -> str:
    """
    Perform comprehensive username reconnaissance across social media platforms and websites.
    
    Searches for username presence across hundreds of social networks and websites 
    to build social media profiles and identify digital footprints for OSINT analysis.
    
    Args:
        username: Target username to search for (e.g., "johndoe", "target_user", "company_name")
        
    Returns:
        String containing social media reconnaissance results including:
        - Found social media profiles with direct URLs
        - Platform availability and account existence status
        - Response timing and detection confidence levels
        - Potential username variations and associated accounts
        - Digital footprint mapping across multiple platforms
        
    LLM Usage Tips:
        - Extract discovered URLs for content analysis with lynx_get_content
        - Use found profiles for additional social engineering intelligence
        - Target associated email domains with dns_lookup and network analysis
        - Combine results with search engine reconnaissance for expanded profiles
        - Analyze username patterns for password policy and security insights
        - Use profile information for targeted phishing and social engineering awareness
    """
    username = sanitize_target(username)
    return run_tool("sherlock", ["--timeout", "3", "--print-found", "--no-color", username])

@mcp.tool()
def whatweb_scan(target: str) -> str:
    """
    Identify web technologies, frameworks, and software components using WhatWeb.
    
    Analyzes websites to identify web technologies, CMS platforms, frameworks, 
    server software, and potential security implications through fingerprinting.
    
    Args:
        target: Target web server URL (e.g., "http://example.com", "https://192.168.1.1:8080")
        
    Returns:
        String containing web technology analysis results including:
        - Web server software and versions (Apache, Nginx, IIS)
        - Content Management Systems (WordPress, Drupal, Joomla)
        - Programming languages and frameworks (PHP, ASP.NET, Django)
        - JavaScript libraries and frameworks (jQuery, React, Angular)
        - Security technologies and configurations (WAF, SSL/TLS)
        
    LLM Usage Tips:
        - Use detected CMS platforms for targeted wpscan_scan analysis
        - Search discovered technologies with searchsploit_query for vulnerabilities
        - Target identified server software versions for exploit research
        - Use framework information for technology-specific vulnerability testing
        - Combine results with nikto_scan for comprehensive web security assessment
        - Extract version numbers for precise vulnerability identification
    """
    target = sanitize_target(target)
    return run_tool("whatweb", ["--no-color", target])

@mcp.tool()
def hping3_ping_scan(target: str) -> str:
    """
    Perform advanced TCP connectivity testing and firewall detection using hping3.
    
    Sends TCP SYN packets to test connectivity when ICMP is blocked or filtered. 
    More reliable than ICMP ping for testing through firewalls and security devices.
    
    Args:
        target: Target hostname or IP address (e.g., "example.com", "192.168.1.1")
        
    Returns:
        String containing TCP connectivity analysis results including:
        - TCP SYN response times and packet loss statistics
        - Port 80 (HTTP) connectivity and firewall bypass capability
        - Advanced network reachability through security devices
        - Packet timing and network performance metrics
        - Firewall detection and filtering analysis
        
    LLM Usage Tips:
        - Use when standard ping_scan fails due to ICMP filtering
        - Combine with nmap_scan results for comprehensive port analysis
        - Test specific services discovered during reconnaissance
        - Analyze timing for network security device detection
        - Use for stealthy connectivity testing and reconnaissance
    """
    target = sanitize_target(target)
    return run_tool("hping3", ["-c", "4", "-S", "-p", "80", target])

@mcp.tool()
def hping3_port_scan(target: str) -> str:
    """
    Perform stealthy TCP SYN port scanning and firewall evasion testing using hping3.
    
    Conducts low-profile port scanning with customizable packet crafting to evade 
    detection and test specific ports through security devices and firewalls.
    
    Args:
        target: Target hostname or IP address (e.g., "example.com", "10.0.0.1")
        
    Returns:
        String containing advanced port scanning results including:
        - TCP port status and response characteristics
        - Firewall and IDS evasion testing results
        - Packet response timing and behavior analysis
        - Service detection through custom packet crafting
        - Stealth scanning capabilities and detection avoidance
        
    LLM Usage Tips:
        - Use for stealthy reconnaissance when nmap_scan is too noisy
        - Test specific ports discovered during initial enumeration
        - Combine with timing analysis for security device detection
        - Use for firewall rule testing and bypass techniques
        - Extract timing patterns for network security analysis
    """
    target = sanitize_target(target)
    return run_tool("hping3", ["-c", "1", "-S", "-p", "80", target])

@mcp.tool()
def hping3_traceroute_scan(target: str) -> str:
    """
    Perform advanced TCP-based network path tracing and firewall mapping using hping3.
    
    Uses TCP packets instead of ICMP for traceroute functionality, enabling path 
    discovery through firewalls and security devices that block traditional traceroute.
    
    Args:
        target: Target hostname or IP address (e.g., "google.com", "172.16.0.1")
        
    Returns:
        String containing TCP traceroute analysis results including:
        - Hop-by-hop TCP response analysis through firewalls
        - Network path discovery with firewall and security device detection
        - Advanced routing analysis through filtered networks
        - TCP-specific network behavior and response patterns
        - Security device detection and network topology mapping
        
    LLM Usage Tips:
        - Use when standard traceroute_scan is blocked by firewalls
        - Extract intermediate IP addresses for geoip_lookup analysis
        - Combine with network scanning for comprehensive infrastructure mapping
        - Analyze security device responses for network defense identification
        - Use timing analysis for network performance and security assessment
    """
    target = sanitize_target(target)
    return run_tool("hping3", ["--traceroute", "-c", "3", "-S", "-p", "80", target])

@mcp.tool()
def arping_scan(target: str) -> str:
    """
    Perform Layer 2 ARP-based host discovery and MAC address enumeration using arping.
    
    Tests host presence and retrieves MAC addresses through ARP requests, enabling 
    local network reconnaissance and device identification on the same subnet.
    
    Args:
        target: Target IP address on local network (e.g., "192.168.1.1", "10.0.0.50")
        
    Returns:
        String containing ARP connectivity analysis results including:
        - MAC address discovery and vendor identification
        - Layer 2 host presence and responsiveness
        - Local network device enumeration and mapping
        - ARP response timing and network performance metrics
        - Hardware vendor information from MAC address prefixes
        
    LLM Usage Tips:
        - Use for local network reconnaissance and device discovery
        - Extract MAC addresses for hardware vendor identification
        - Combine with nmap_scan for comprehensive local network mapping
        - Use timing information for network performance analysis
        - Essential for internal network penetration testing scenarios
    """
    target = sanitize_target(target)
    return run_tool("arping", ["-c", "4", target])

@mcp.tool()
def photon_scan(target: str) -> str:
    """
    Perform intelligent web crawling and OSINT data extraction using Photon.
    
    Advanced web crawler that extracts URLs, email addresses, social media links, 
    and other valuable intelligence from web applications for reconnaissance.
    
    Args:
        target: Target website URL (e.g., "http://example.com", "https://company.com")
        
    Returns:
        String containing web intelligence gathering results including:
        - Comprehensive URL discovery and site mapping
        - Extracted email addresses and contact information
        - Social media profiles and external service links
        - JavaScript files and API endpoints
        - Hidden pages and administrative interfaces
        
    LLM Usage Tips:
        - Use discovered URLs as targets for nikto_scan and dirb_scan analysis
        - Extract email addresses for social engineering and OSINT research
        - Target found API endpoints with sqlmap_scan for injection testing
        - Use JavaScript files and admin interfaces for further reconnaissance
        - Combine results with lynx_extract_links for comprehensive site mapping
        - Analyze social media links with sherlock_scan for expanded OSINT
    """
    target = sanitize_target(target)
    return run_tool("photon", ["-u", target, "-l", "2", "--only-urls", "--timeout", "30"])

@mcp.tool()
def lynx_extract_links(target: str) -> str:
    """
    Extract and enumerate all hyperlinks from web pages using the Lynx text browser.
    
    Provides comprehensive link extraction from web pages, including both visible 
    and hidden links, for website mapping and attack surface enumeration.
    
    Args:
        target: Target web page URL (e.g., "http://example.com/page.html", "https://site.com")
        
    Returns:
        String containing complete link enumeration results including:
        - All hyperlinks found on the target page
        - Internal site navigation and structure mapping
        - External links and third-party integrations
        - Form action URLs and API endpoints
        - Resource links (CSS, JavaScript, images, documents)
        
    LLM Usage Tips:
        - Use extracted URLs as targets for individual security testing tools
        - Target internal links with dirb_scan and nikto_scan for vulnerability analysis
        - Test form action URLs with sqlmap_scan for injection vulnerabilities
        - Analyze external links for third-party attack vectors and intelligence
        - Combine with photon_scan results for comprehensive site mapping
        - Use API endpoints and resources for further reconnaissance and testing
    """
    target = sanitize_target(target)
    return run_tool("lynx", ["-dump", "-listonly", target])

@mcp.tool()
def lynx_get_content(target: str) -> str:
    """
    Retrieve and format web page content for LLM analysis and manual inspection.
    
    Converts web pages to clean, formatted text optimized for LLM processing and analysis, 
    removing HTML formatting while preserving content structure and readability.
    
    Args:
        target: Target web page URL (e.g., "http://example.com/admin", "https://site.com/login")
        
    Returns:
        String containing clean, formatted web page content including:
        - Plain text content with preserved structure and formatting
        - Form fields, input elements, and interactive components
        - Error messages, system information, and diagnostic content
        - Navigation menus and site structure information
        - Text optimized for LLM analysis and pattern recognition
        
    LLM Usage Tips:
        - Analyze extracted content for sensitive information disclosure
        - Identify form fields and parameters for sqlmap_scan injection testing
        - Extract system information and error messages for vulnerability research
        - Use content analysis for social engineering intelligence gathering
        - Identify authentication mechanisms and security implementations
        - Parse application behavior and functionality for attack vector identification
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
