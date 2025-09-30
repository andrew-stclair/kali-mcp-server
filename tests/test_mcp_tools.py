"""Tests for all MCP tool functions in the Kali MCP Pentest Server."""

import pytest
from unittest.mock import patch, Mock
from main import (
    nmap_scan, nikto_scan, sqlmap_scan, wpscan_scan, dirb_scan,
    searchsploit_query, ping_scan, traceroute_scan, gobuster_dir_scan,
    gobuster_dns_scan, gobuster_vhost_scan, sherlock_scan, whatweb_scan,
    hping3_ping_scan, hping3_port_scan, hping3_traceroute_scan,
    arping_scan, photon_scan
)


class TestNetworkScanningTools:
    """Test network scanning and reconnaissance tools."""
    
    def test_nmap_scan_valid_target(self, mock_subprocess_run, sample_targets):
        """Test nmap_scan with valid target."""
        target = sample_targets['valid_ip']
        result = nmap_scan(target)
        
        assert isinstance(result, str)
        mock_subprocess_run.assert_called_with(
            ['nmap', '-Pn', target],
            capture_output=True,
            text=True,
            timeout=120
        )
    
    def test_nmap_scan_dangerous_input(self, sample_targets):
        """Test nmap_scan rejects dangerous input."""
        with pytest.raises(ValueError, match="Invalid target: contains dangerous characters"):
            nmap_scan(sample_targets['dangerous_input'])
    
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
            ['sherlock', '--timeout', '30', '--print-found', '--no-color', username],
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
        ping_scan, traceroute_scan, gobuster_dir_scan, gobuster_dns_scan,
        gobuster_vhost_scan, whatweb_scan, hping3_ping_scan, hping3_port_scan,
        hping3_traceroute_scan, arping_scan, photon_scan
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
        searchsploit_query, ping_scan, traceroute_scan, gobuster_dir_scan,
        gobuster_dns_scan, gobuster_vhost_scan, sherlock_scan, whatweb_scan,
        hping3_ping_scan, hping3_port_scan, hping3_traceroute_scan,
        arping_scan, photon_scan
    ])
    def test_all_tools_return_string(self, tool_func, sample_targets, mock_subprocess_run):
        """Test that all tools return string results."""
        # Use appropriate sample target based on tool
        if tool_func in [sqlmap_scan, wpscan_scan, dirb_scan, gobuster_dir_scan, 
                         gobuster_vhost_scan, whatweb_scan, photon_scan]:
            target = sample_targets['valid_url']
        elif tool_func in [searchsploit_query]:
            target = sample_targets['valid_query']
        elif tool_func in [sherlock_scan]:
            target = sample_targets['valid_username']
        else:
            target = sample_targets['valid_ip']
        
        result = tool_func(target)
        assert isinstance(result, str)
        assert len(result) > 0