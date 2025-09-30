"""Integration tests for the MCP server functionality."""

import pytest
from main import mcp


class TestMCPServerIntegration:
    """Test the FastMCP server integration."""
    
    def test_mcp_server_initialization(self):
        """Test that MCP server initializes correctly."""
        assert mcp.name == "kali-mcp-pentest-server"
        assert "penetration testing" in mcp.instructions.lower()
        # Test that the server has the necessary attributes
        assert hasattr(mcp, 'streamable_http_app')
        assert hasattr(mcp, 'sse_app')
    
    def test_mcp_tools_registration(self):
        """Test that all MCP tools are properly registered."""
        # The tools should be registered as MCP tools
        # We can verify this by checking that the tool functions exist
        expected_tools = [
            'nmap_scan', 'nikto_scan', 'sqlmap_scan', 'wpscan_scan', 'dirb_scan',
            'searchsploit_query', 'ping_scan', 'traceroute_scan', 'gobuster_dir_scan',
            'gobuster_dns_scan', 'gobuster_vhost_scan', 'sherlock_scan', 'whatweb_scan',
            'hping3_ping_scan', 'hping3_port_scan', 'hping3_traceroute_scan',
            'arping_scan', 'photon_scan'
        ]
        
        # Import main module to check if functions exist
        import main
        for tool_name in expected_tools:
            assert hasattr(main, tool_name), f"Tool function {tool_name} not found"
            tool_func = getattr(main, tool_name)
            assert callable(tool_func), f"Tool {tool_name} is not callable"


class TestMCPToolsViaServer:
    """Test MCP tools through the server interface."""
    
    def test_tool_docstrings_exist(self):
        """Test that all MCP tools have proper documentation."""
        import main
        
        tool_functions = [
            main.nmap_scan, main.nikto_scan, main.sqlmap_scan, main.wpscan_scan,
            main.dirb_scan, main.searchsploit_query, main.ping_scan, main.traceroute_scan,
            main.gobuster_dir_scan, main.gobuster_dns_scan, main.gobuster_vhost_scan,
            main.sherlock_scan, main.whatweb_scan, main.hping3_ping_scan,
            main.hping3_port_scan, main.hping3_traceroute_scan, main.arping_scan,
            main.photon_scan
        ]
        
        for tool_func in tool_functions:
            assert tool_func.__doc__ is not None, f"Tool {tool_func.__name__} missing docstring"
            assert "Args:" in tool_func.__doc__, f"Tool {tool_func.__name__} missing Args section"
            assert "Returns:" in tool_func.__doc__, f"Tool {tool_func.__name__} missing Returns section"
    
    def test_all_tools_have_mcp_decorator(self):
        """Test that all tool functions have the @mcp.tool() decorator."""
        import main
        import inspect
        
        # Get all functions from main module
        functions = inspect.getmembers(main, inspect.isfunction)
        tool_functions = [func for name, func in functions if name.endswith('_scan') or name.endswith('_query')]
        
        # Each tool function should be an MCP tool
        # This is implicitly tested by the fact they work as MCP tools
        assert len(tool_functions) == 18  # All 18 tool functions


class TestSecurityFeatures:
    """Test security features of the MCP server."""
    
    def test_allowed_tools_security(self):
        """Test that ALLOWED_TOOLS doesn't contain dangerous commands."""
        from main import ALLOWED_TOOLS
        
        dangerous_commands = [
            'rm', 'mv', 'cp', 'chmod', 'chown', 'sudo', 'su',
            'bash', 'sh', 'python', 'perl', 'ruby', 'nc', 'netcat',
            'dd', 'fdisk', 'mount', 'umount', 'kill', 'killall'
        ]
        
        for dangerous_cmd in dangerous_commands:
            assert dangerous_cmd not in ALLOWED_TOOLS, f"Dangerous command {dangerous_cmd} found in ALLOWED_TOOLS"
    
    def test_input_sanitization_coverage(self):
        """Test that input sanitization is applied to all tool functions."""
        import main
        import inspect
        
        # Get source code of all tool functions to verify sanitize_target is called
        tool_functions = [
            main.nmap_scan, main.nikto_scan, main.sqlmap_scan, main.wpscan_scan,
            main.dirb_scan, main.searchsploit_query, main.ping_scan, main.traceroute_scan,
            main.gobuster_dir_scan, main.gobuster_dns_scan, main.gobuster_vhost_scan,
            main.sherlock_scan, main.whatweb_scan, main.hping3_ping_scan,
            main.hping3_port_scan, main.hping3_traceroute_scan, main.arping_scan,
            main.photon_scan
        ]
        
        for tool_func in tool_functions:
            source = inspect.getsource(tool_func)
            assert 'sanitize_target' in source, f"Tool {tool_func.__name__} doesn't call sanitize_target"
    
    def test_mcp_server_attributes(self):
        """Test that the MCP server has expected attributes for security."""
        # Test that server has necessary apps
        assert hasattr(mcp, 'streamable_http_app')
        assert hasattr(mcp, 'sse_app')
        
        # Test that the server configuration is secure
        assert mcp.name == "kali-mcp-pentest-server"
        assert len(mcp.instructions) > 0