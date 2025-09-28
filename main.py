import os
import subprocess
from fastapi import FastAPI, Form, HTTPException
from fastapi.responses import PlainTextResponse

app = FastAPI()

# Environment config
ALLOWED_TOOLS = ["nmap", "nikto", "sqlmap", "wpscan", "dirb", "searchsploit"]

# Input sanitization helper
def sanitize_target(target: str) -> str:
    if not target or any(c in target for c in ";&|$`\n\r"):
        raise HTTPException(status_code=400, detail="Invalid target")
    return target.strip()

def run_tool(tool: str, args: list) -> str:
    if tool not in ALLOWED_TOOLS:
        raise HTTPException(status_code=400, detail="Tool not allowed")
    cmd = [tool] + args
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        return result.stdout + "\n" + result.stderr
    except Exception as e:
        return f"Error running {tool}: {str(e)}"

@app.post("/nmap", response_class=PlainTextResponse)
def nmap_scan(target: str = Form(...)):
    target = sanitize_target(target)
    return run_tool("nmap", ["-Pn", target])

@app.post("/nikto", response_class=PlainTextResponse)
def nikto_scan(target: str = Form(...)):
    target = sanitize_target(target)
    return run_tool("nikto", ["-h", target])

@app.post("/sqlmap", response_class=PlainTextResponse)
def sqlmap_scan(target: str = Form(...)):
    target = sanitize_target(target)
    return run_tool("sqlmap", ["-u", target, "--batch"])

@app.post("/wpscan", response_class=PlainTextResponse)
def wpscan_scan(target: str = Form(...)):
    target = sanitize_target(target)
    return run_tool("wpscan", ["--url", target])

@app.post("/dirb", response_class=PlainTextResponse)
def dirb_scan(target: str = Form(...)):
    target = sanitize_target(target)
    return run_tool("dirb", [target])

@app.post("/searchsploit", response_class=PlainTextResponse)
def searchsploit_query(query: str = Form(...)):
    query = sanitize_target(query)
    return run_tool("searchsploit", [query])

@app.get("/")
def root():
    return {"message": "Kali MCP Pentest Server running"}
