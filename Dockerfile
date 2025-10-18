FROM kalilinux/kali-rolling

# Install required tools
RUN apt-get update && apt-get install -y \
    nmap nikto sqlmap wpscan dirb gobuster seclists exploitdb sherlock whatweb python3 python3-pip python3-venv sudo libcap2-bin \
    iputils-ping traceroute hping3 arping photon lynx && \
    rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN useradd -m kaliuser && echo 'kaliuser ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers

# Copy MCP server code as root and set ownership
COPY . /home/kaliuser/app
RUN chown -R kaliuser:kaliuser /home/kaliuser/app

# Set capabilities for nmap, hping3, and arping (if needed)
RUN setcap cap_net_raw,cap_net_admin,cap_net_bind_service+eip /usr/bin/nmap && \
    setcap cap_net_raw,cap_net_admin,cap_net_bind_service+eip /usr/sbin/hping3 && \
    setcap cap_net_raw,cap_net_admin,cap_net_bind_service+eip /usr/sbin/arping

# Switch to non-root user
USER kaliuser
WORKDIR /home/kaliuser/app

# Create virtual environment and install Python dependencies
RUN python3 -m venv venv && \
    venv/bin/pip install --upgrade pip && \
    venv/bin/pip install -r requirements.txt

EXPOSE 8080
CMD ["./venv/bin/python", "main.py"]
