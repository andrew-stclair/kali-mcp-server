"""Tests for all MCP tool functions in the Kali MCP Pentest Server."""

import pytest
from unittest.mock import patch, Mock
from main import (
    nmap_scan, nikto_scan, sqlmap_scan, wpscan_scan, dirb_scan,
    searchsploit_query, ping_scan, traceroute_scan, dns_lookup, geoip_lookup, gobuster_dir_scan,
    gobuster_dns_scan, gobuster_vhost_scan, sherlock_scan, whatweb_scan,
    hping3_ping_scan, hping3_port_scan, hping3_traceroute_scan,
    arping_scan, photon_scan, lynx_extract_links, lynx_get_content
)


class TestNetworkScanningTools:
    """Test network scanning and reconnaissance tools."""
    
    def test_nmap_scan_valid_target_default_ports(self, mock_subprocess_run, sample_targets):
        """Test nmap_scan with valid target using default ports."""
        target = sample_targets['valid_ip']
        result = nmap_scan(target)
        
        assert isinstance(result, str)
        mock_subprocess_run.assert_called_with(
            ['nmap', '-Pn', '-p', '21,22,23,25,80,443,3306,3389,5432,8080', target],
            capture_output=True,
            text=True,
            timeout=120
        )
    
    def test_nmap_scan_valid_target_custom_ports(self, mock_subprocess_run, sample_targets):
        """Test nmap_scan with valid target and custom ports."""
        target = sample_targets['valid_ip']
        ports = "80,443,8080"
        result = nmap_scan(target, ports)
        
        assert isinstance(result, str)
        mock_subprocess_run.assert_called_with(
            ['nmap', '-Pn', '-p', ports, target],
            capture_output=True,
            text=True,
            timeout=120
        )
    
    def test_nmap_scan_valid_target_port_range(self, mock_subprocess_run, sample_targets):
        """Test nmap_scan with valid target and port range."""
        target = sample_targets['valid_ip']
        ports = "1-1000"
        result = nmap_scan(target, ports)
        
        assert isinstance(result, str)
        mock_subprocess_run.assert_called_with(
            ['nmap', '-Pn', '-p', ports, target],
            capture_output=True,
            text=True,
            timeout=120
        )
    
    def test_nmap_scan_dangerous_input_target(self, sample_targets):
        """Test nmap_scan rejects dangerous input in target."""
        with pytest.raises(ValueError, match="Invalid target: contains dangerous characters"):
            nmap_scan(sample_targets['dangerous_input'])
    
    def test_nmap_scan_dangerous_input_ports(self, sample_targets):
        """Test nmap_scan rejects dangerous input in ports."""
        target = sample_targets['valid_ip']
        with pytest.raises(ValueError, match="Invalid target: contains dangerous characters"):
            nmap_scan(target, sample_targets['dangerous_input'])
    
    def test_ping_scan_valid_target(self, mock_subprocess_run, sample_targets):
        """Test ping_scan with valid target."""
        target = sample_targets['valid_hostname']
        result = ping_scan(target)
        
        assert isinstance(result, str)
        mock_subprocess_run.assert_called_with(
            ['ping', '-c', '4', target],
            capture_output=True,
            text=True,
            timeout=120
        )
    
    def test_traceroute_scan_valid_target(self, mock_subprocess_run, sample_targets):
        """Test traceroute_scan with valid target."""
        target = sample_targets['valid_ip']
        result = traceroute_scan(target)
        
        assert isinstance(result, str)
        mock_subprocess_run.assert_called_with(
            ['traceroute', target],
            capture_output=True,
            text=True,
            timeout=120
        )

    def test_dns_lookup_valid_target(self, mock_subprocess_run, sample_targets):
        """Test dns_lookup with valid domain."""
        target = sample_targets['valid_hostname']
        result = dns_lookup(target)
        
        assert isinstance(result, str)
        mock_subprocess_run.assert_called_with(
            ['dig', 'ANY', target, '+noall', '+answer', '+additional'],
            capture_output=True,
            text=True,
            timeout=120
        )

    def test_dns_lookup_dangerous_input(self, sample_targets):
        """Test dns_lookup rejects dangerous input."""
        with pytest.raises(ValueError, match="Invalid target: contains dangerous characters"):
            dns_lookup(sample_targets['dangerous_input'])

    def test_geoip_lookup_valid_ipv4(self, mock_subprocess_run, sample_targets):
        """Test geoip_lookup with valid IPv4 address."""
        target = sample_targets['valid_ip']
        result = geoip_lookup(target)
        
        assert isinstance(result, str)
        mock_subprocess_run.assert_called_with(
            ['geoiplookup', target],
            capture_output=True,
            text=True,
            timeout=120
        )

    def test_geoip_lookup_valid_ipv6(self, mock_subprocess_run):
        """Test geoip_lookup with valid IPv6 address."""
        target = "2001:4860:4860::8888"  # Google's IPv6 DNS
        result = geoip_lookup(target)
        
        assert isinstance(result, str)
        mock_subprocess_run.assert_called_with(
            ['geoiplookup', target],
            capture_output=True,
            text=True,
            timeout=120
        )

    def test_geoip_lookup_invalid_ip(self):
        """Test geoip_lookup rejects invalid IP addresses."""
        with pytest.raises(ValueError, match="Invalid IP address: not a valid IPv4 or IPv6 address"):
            geoip_lookup("invalid_ip")
        
        with pytest.raises(ValueError, match="Invalid IP address: not a valid IPv4 or IPv6 address"):
            geoip_lookup("256.256.256.256")
        
        with pytest.raises(ValueError, match="Invalid IP address: not a valid IPv4 or IPv6 address"):
            geoip_lookup("example.com")

    def test_geoip_lookup_dangerous_input(self, sample_targets):
        """Test geoip_lookup rejects dangerous input."""
        with pytest.raises(ValueError, match="Invalid IP address"):
            geoip_lookup(sample_targets['dangerous_input'])


class TestWebScanningTools:
    """Test web application scanning tools."""
    
    def test_nikto_scan_valid_target(self, mock_subprocess_run, sample_targets):
        """Test nikto_scan with valid target."""
        target = sample_targets['valid_hostname']
        result = nikto_scan(target)
        
        assert isinstance(result, str)
        mock_subprocess_run.assert_called_with(
            ['nikto', '-h', target],
            capture_output=True,
            text=True,
            timeout=120
        )
    
    def test_sqlmap_scan_valid_target(self, mock_subprocess_run, sample_targets):
        """Test sqlmap_scan with valid URL."""
        target = sample_targets['valid_url']
        result = sqlmap_scan(target)
        
        assert isinstance(result, str)
        mock_subprocess_run.assert_called_with(
            ['sqlmap', '-u', target, '--batch'],
            capture_output=True,
            text=True,
            timeout=120
        )
    
    def test_wpscan_scan_valid_target(self, mock_subprocess_run, sample_targets):
        """Test wpscan_scan with valid WordPress URL."""
        target = sample_targets['valid_url']
        result = wpscan_scan(target)
        
        assert isinstance(result, str)
        mock_subprocess_run.assert_called_with(
            ['wpscan', '--url', target],
            capture_output=True,
            text=True,
            timeout=120
        )
    
    def test_dirb_scan_valid_target(self, mock_subprocess_run, sample_targets):
        """Test dirb_scan with valid URL."""
        target = sample_targets['valid_url']
        result = dirb_scan(target)
        
        assert isinstance(result, str)
        mock_subprocess_run.assert_called_with(
            ['dirb', target],
            capture_output=True,
            text=True,
            timeout=120
        )
    
    def test_whatweb_scan_valid_target(self, mock_subprocess_run, sample_targets):
        """Test whatweb_scan with valid URL."""
        target = sample_targets['valid_url']
        result = whatweb_scan(target)
        
        assert isinstance(result, str)
        mock_subprocess_run.assert_called_with(
            ['whatweb', '--no-color', target],
            capture_output=True,
            text=True,
            timeout=120
        )

    def test_lynx_extract_links_valid_target(self, mock_subprocess_run, sample_targets):
        """Test lynx_extract_links with valid URL."""
        target = sample_targets['valid_url']
        result = lynx_extract_links(target)
        
        assert isinstance(result, str)
        mock_subprocess_run.assert_called_with(
            ['lynx', '-dump', '-listonly', target],
            capture_output=True,
            text=True,
            timeout=120
        )

    def test_lynx_get_content_valid_target(self, mock_subprocess_run, sample_targets):
        """Test lynx_get_content with valid URL."""
        target = sample_targets['valid_url']
        result = lynx_get_content(target)
        
        assert isinstance(result, str)
        mock_subprocess_run.assert_called_with(
            ['lynx', '-dump', '-nolist', '-width=120', target],
            capture_output=True,
            text=True,
            timeout=120
        )

    def test_lynx_extract_links_dangerous_input(self, sample_targets):
        """Test lynx_extract_links rejects dangerous input."""
        with pytest.raises(ValueError, match="Invalid target: contains dangerous characters"):
            lynx_extract_links(sample_targets['dangerous_input'])

    def test_lynx_get_content_dangerous_input(self, sample_targets):
        """Test lynx_get_content rejects dangerous input."""
        with pytest.raises(ValueError, match="Invalid target: contains dangerous characters"):
            lynx_get_content(sample_targets['dangerous_input'])


class TestGobusterTools:
    """Test Gobuster brute force scanning tools."""
    
    def test_gobuster_dir_scan_valid_target(self, mock_subprocess_run, sample_targets):
        """Test gobuster_dir_scan with valid URL."""
        target = sample_targets['valid_url']
        result = gobuster_dir_scan(target)
        
        assert isinstance(result, str)
        mock_subprocess_run.assert_called_with(
            ['gobuster', 'dir', '-u', target, '-w', '/usr/share/seclists/Discovery/Web-Content/common.txt'],
            capture_output=True,
            text=True,
            timeout=120
        )
    
    def test_gobuster_dns_scan_valid_target(self, mock_subprocess_run, sample_targets):
        """Test gobuster_dns_scan with valid domain."""
        target = sample_targets['valid_hostname']
        result = gobuster_dns_scan(target)
        
        assert isinstance(result, str)
        mock_subprocess_run.assert_called_with(
            ['gobuster', 'dns', '-d', target, '-w', '/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt'],
            capture_output=True,
            text=True,
            timeout=120
        )
    
    def test_gobuster_vhost_scan_valid_target(self, mock_subprocess_run, sample_targets):
        """Test gobuster_vhost_scan with valid URL."""
        target = sample_targets['valid_url']
        result = gobuster_vhost_scan(target)
        
        assert isinstance(result, str)
        mock_subprocess_run.assert_called_with(
            ['gobuster', 'vhost', '-u', target, '-w', '/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt'],
            capture_output=True,
            text=True,
            timeout=120
        )


class TestReconnaissanceTools:
    """Test reconnaissance and OSINT tools."""
    
    def test_searchsploit_query_valid_input(self, mock_subprocess_run, sample_targets):
        """Test searchsploit_query with valid search term."""
        query = sample_targets['valid_query']
        result = searchsploit_query(query)
        
        assert isinstance(result, str)
        mock_subprocess_run.assert_called_with(
            ['searchsploit', query],
            capture_output=True,
            text=True,
            timeout=120
        )
    
    def test_sherlock_scan_valid_username(self, mock_subprocess_run, sample_targets):
        """Test sherlock_scan with valid username."""
        username = sample_targets['valid_username']
        result = sherlock_scan(username)
        
        assert isinstance(result, str)
        mock_subprocess_run.assert_called_with(
            ['sherlock', '--timeout', '3', '--print-found', '--no-color', username],
            capture_output=True,
            text=True,
            timeout=120
        )
    
    def test_photon_scan_valid_target(self, mock_subprocess_run, sample_targets):
        """Test photon_scan with valid URL."""
        target = sample_targets['valid_url']
        result = photon_scan(target)
        
        assert isinstance(result, str)
        mock_subprocess_run.assert_called_with(
            ['photon', '-u', target, '-l', '2', '--only-urls', '--timeout', '30'],
            capture_output=True,
            text=True,
            timeout=120
        )


class TestHping3Tools:
    """Test hping3 advanced network testing tools."""
    
    def test_hping3_ping_scan_valid_target(self, mock_subprocess_run, sample_targets):
        """Test hping3_ping_scan with valid target."""
        target = sample_targets['valid_ip']
        result = hping3_ping_scan(target)
        
        assert isinstance(result, str)
        mock_subprocess_run.assert_called_with(
            ['hping3', '-c', '4', '-S', '-p', '80', target],
            capture_output=True,
            text=True,
            timeout=120
        )
    
    def test_hping3_port_scan_valid_target(self, mock_subprocess_run, sample_targets):
        """Test hping3_port_scan with valid target."""
        target = sample_targets['valid_ip']
        result = hping3_port_scan(target)
        
        assert isinstance(result, str)
        mock_subprocess_run.assert_called_with(
            ['hping3', '-c', '1', '-S', '-p', '80', target],
            capture_output=True,
            text=True,
            timeout=120
        )
    
    def test_hping3_traceroute_scan_valid_target(self, mock_subprocess_run, sample_targets):
        """Test hping3_traceroute_scan with valid target."""
        target = sample_targets['valid_ip']
        result = hping3_traceroute_scan(target)
        
        assert isinstance(result, str)
        mock_subprocess_run.assert_called_with(
            ['hping3', '--traceroute', '-c', '3', '-S', '-p', '80', target],
            capture_output=True,
            text=True,
            timeout=120
        )
    
    def test_arping_scan_valid_target(self, mock_subprocess_run, sample_targets):
        """Test arping_scan with valid target."""
        target = sample_targets['valid_ip']
        result = arping_scan(target)
        
        assert isinstance(result, str)
        mock_subprocess_run.assert_called_with(
            ['arping', '-c', '4', target],
            capture_output=True,
            text=True,
            timeout=120
        )


class TestInputValidationAcrossAllTools:
    """Test that all tools properly validate inputs."""
    
    @pytest.mark.parametrize("tool_func", [
        nmap_scan, nikto_scan, sqlmap_scan, wpscan_scan, dirb_scan,
        ping_scan, traceroute_scan, dns_lookup, gobuster_dir_scan, gobuster_dns_scan,
        gobuster_vhost_scan, whatweb_scan, hping3_ping_scan, hping3_port_scan,
        hping3_traceroute_scan, arping_scan, photon_scan, lynx_extract_links, lynx_get_content
    ])
    def test_all_tools_reject_dangerous_input(self, tool_func, sample_targets):
        """Test that all tools reject dangerous input."""
        with pytest.raises(ValueError, match="Invalid target: contains dangerous characters"):
            tool_func(sample_targets['dangerous_input'])
    
    @pytest.mark.parametrize("tool_func", [
        searchsploit_query, sherlock_scan
    ])
    def test_query_tools_reject_dangerous_input(self, tool_func, sample_targets):
        """Test that query-based tools reject dangerous input."""
        with pytest.raises(ValueError, match="Invalid target: contains dangerous characters"):
            tool_func(sample_targets['malicious_input'])
    
    @pytest.mark.parametrize("tool_func", [
        nmap_scan, nikto_scan, sqlmap_scan, wpscan_scan, dirb_scan,
        searchsploit_query, ping_scan, traceroute_scan, dns_lookup, geoip_lookup, gobuster_dir_scan,
        gobuster_dns_scan, gobuster_vhost_scan, sherlock_scan, whatweb_scan,
        hping3_ping_scan, hping3_port_scan, hping3_traceroute_scan,
        arping_scan, photon_scan, lynx_extract_links, lynx_get_content
    ])
    def test_all_tools_return_string(self, tool_func, sample_targets, mock_subprocess_run):
        """Test that all tools return string results."""
        # Use appropriate sample target based on tool
        if tool_func in [sqlmap_scan, wpscan_scan, dirb_scan, gobuster_dir_scan, 
                         gobuster_vhost_scan, whatweb_scan, photon_scan, lynx_extract_links, lynx_get_content]:
            target = sample_targets['valid_url']
        elif tool_func in [searchsploit_query]:
            target = sample_targets['valid_query']
        elif tool_func in [sherlock_scan]:
            target = sample_targets['valid_username']
        elif tool_func in [dns_lookup]:
            target = sample_targets['valid_hostname']
        else:
            target = sample_targets['valid_ip']
        
        result = tool_func(target)
        assert isinstance(result, str)
        assert len(result) > 0