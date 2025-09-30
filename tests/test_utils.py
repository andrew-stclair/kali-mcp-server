"""Tests for utility functions in the Kali MCP Pentest Server."""

import pytest
from unittest.mock import patch, Mock
import subprocess
from main import sanitize_target, run_tool, ALLOWED_TOOLS


class TestSanitizeTarget:
    """Test the input sanitization function."""
    
    def test_sanitize_target_valid_input(self):
        """Test sanitization with valid inputs."""
        valid_inputs = [
            "127.0.0.1",
            "example.com",
            "http://example.com",
            "subdomain.example.com",
            "192.168.1.1",
            "testuser123",
            "   127.0.0.1   "  # Should strip whitespace
        ]
        
        for input_val in valid_inputs:
            result = sanitize_target(input_val)
            assert isinstance(result, str)
            assert result == input_val.strip()
    
    def test_sanitize_target_dangerous_characters(self):
        """Test that dangerous characters are rejected."""
        dangerous_inputs = [
            "127.0.0.1; rm -rf /",
            "example.com & malicious_command",
            "127.0.0.1 | cat /etc/passwd",
            "example.com$malicious",
            "127.0.0.1`whoami`",
            "example.com\nmalicious",
            "127.0.0.1\rmalicious"
        ]
        
        for dangerous_input in dangerous_inputs:
            with pytest.raises(ValueError, match="Invalid target: contains dangerous characters"):
                sanitize_target(dangerous_input)
    
    def test_sanitize_target_empty_input(self):
        """Test that empty inputs are rejected."""
        empty_inputs = ["", None]
        
        for empty_input in empty_inputs:
            with pytest.raises(ValueError, match="Invalid target: contains dangerous characters"):
                sanitize_target(empty_input)
        
        # Spaces should be stripped and result in empty string, which should raise an error after stripping
        with pytest.raises(ValueError, match="Invalid target: contains dangerous characters"):
            sanitize_target("   ")


class TestRunTool:
    """Test the tool execution function."""
    
    def test_run_tool_allowed_tools(self, mock_subprocess_run):
        """Test that allowed tools can be executed."""
        for tool in ALLOWED_TOOLS:
            result = run_tool(tool, ["--help"])
            assert isinstance(result, str)
            assert "Mock tool output" in result
            mock_subprocess_run.assert_called()
    
    def test_run_tool_disallowed_tool(self):
        """Test that disallowed tools are rejected."""
        with pytest.raises(ValueError, match="Tool not allowed: malicious_tool"):
            run_tool("malicious_tool", ["arg1"])
    
    def test_run_tool_command_construction(self, mock_subprocess_run):
        """Test that commands are constructed correctly."""
        tool = "nmap"
        args = ["-Pn", "127.0.0.1"]
        
        run_tool(tool, args)
        
        expected_cmd = [tool] + args
        mock_subprocess_run.assert_called_with(
            expected_cmd, 
            capture_output=True, 
            text=True, 
            timeout=120
        )
    
    def test_run_tool_timeout_handling(self, mock_subprocess_run):
        """Test that timeout is properly configured."""
        run_tool("ping", ["-c", "1", "127.0.0.1"])
        
        # Verify timeout is set to 120 seconds
        mock_subprocess_run.assert_called_with(
            ["ping", "-c", "1", "127.0.0.1"],
            capture_output=True,
            text=True,
            timeout=120
        )
    
    def test_run_tool_exception_handling(self):
        """Test exception handling in run_tool."""
        with patch('subprocess.run', side_effect=subprocess.TimeoutExpired("cmd", 120)):
            result = run_tool("ping", ["-c", "1", "127.0.0.1"])
            assert "Error running ping:" in result
            assert "timed out" in result
    
    def test_run_tool_output_combination(self, mock_subprocess_run):
        """Test that stdout and stderr are combined correctly."""
        mock_subprocess_run.return_value = Mock(
            stdout="Standard output",
            stderr="Standard error",
            returncode=0
        )
        
        result = run_tool("nmap", ["-Pn", "127.0.0.1"])
        
        assert "Standard output" in result
        assert "Standard error" in result
        assert result == "Standard output\nStandard error"


class TestAllowedTools:
    """Test the ALLOWED_TOOLS configuration."""
    
    def test_allowed_tools_list_exists(self):
        """Test that ALLOWED_TOOLS is properly defined."""
        assert isinstance(ALLOWED_TOOLS, list)
        assert len(ALLOWED_TOOLS) > 0
    
    def test_expected_tools_in_allowed_list(self):
        """Test that all expected security tools are in the allowed list."""
        expected_tools = [
            "nmap", "nikto", "sqlmap", "wpscan", "dirb", "searchsploit",
            "ping", "traceroute", "gobuster", "sherlock", "whatweb",
            "hping3", "arping", "photon"
        ]
        
        for tool in expected_tools:
            assert tool in ALLOWED_TOOLS, f"Expected tool '{tool}' not found in ALLOWED_TOOLS"
    
    def test_no_dangerous_tools_in_allowed_list(self):
        """Test that dangerous system tools are not in the allowed list."""
        dangerous_tools = [
            "rm", "mv", "cp", "chmod", "chown", "sudo", "su",
            "bash", "sh", "python", "perl", "ruby", "nc", "netcat"
        ]
        
        for dangerous_tool in dangerous_tools:
            assert dangerous_tool not in ALLOWED_TOOLS, f"Dangerous tool '{dangerous_tool}' found in ALLOWED_TOOLS"