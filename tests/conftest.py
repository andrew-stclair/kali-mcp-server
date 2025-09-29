"""Test configuration and fixtures for the Kali MCP Pentest Server."""

import pytest
from unittest.mock import Mock, patch
import subprocess


@pytest.fixture
def mock_subprocess_run():
    """Mock subprocess.run to avoid executing actual security tools during tests."""
    with patch('subprocess.run') as mock_run:
        # Default successful response
        mock_run.return_value = Mock(
            stdout="Mock tool output",
            stderr="Mock stderr",
            returncode=0
        )
        yield mock_run


@pytest.fixture
def sample_targets():
    """Provide sample target inputs for testing."""
    return {
        'valid_ip': '127.0.0.1',
        'valid_hostname': 'example.com',
        'valid_url': 'http://example.com',
        'valid_username': 'testuser',
        'valid_query': 'apache',
        'dangerous_input': '127.0.0.1; rm -rf /',
        'malicious_input': '$(malicious_command)',
        'pipe_input': '127.0.0.1 | cat /etc/passwd'
    }


@pytest.fixture
def expected_tool_commands():
    """Expected command structures for each tool."""
    return {
        'nmap': ['nmap', '-Pn'],
        'nikto': ['nikto', '-h'],
        'sqlmap': ['sqlmap', '-u', '', '--batch'],
        'wpscan': ['wpscan', '--url'],
        'dirb': ['dirb'],
        'searchsploit': ['searchsploit'],
        'ping': ['ping', '-c', '4'],
        'traceroute': ['traceroute'],
        'gobuster_dir': ['gobuster', 'dir', '-u', '', '-w', '/usr/share/seclists/Discovery/Web-Content/common.txt'],
        'gobuster_dns': ['gobuster', 'dns', '-d', '', '-w', '/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt'],
        'gobuster_vhost': ['gobuster', 'vhost', '-u', '', '-w', '/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt'],
        'sherlock': ['sherlock', '--timeout', '30', '--print-found', '--no-color'],
        'whatweb': ['whatweb', '--no-color'],
        'hping3_ping': ['hping3', '-c', '4', '-S', '-p', '80'],
        'hping3_port': ['hping3', '-c', '1', '-S', '-p', '++80'],
        'hping3_traceroute': ['hping3', '--traceroute', '-c', '3', '-S', '-p', '80'],
        'arping': ['arping', '-c', '4'],
        'photon': ['photon', '-u', '', '-l', '2', '--only-urls', '--timeout', '30']
    }