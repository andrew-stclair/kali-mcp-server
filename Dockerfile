FROM kalilinux/kali-rolling

# Install required tools
RUN apt-get update && apt-get install -y \
    nmap nikto sqlmap wpscan dirb exploitdb python3 python3-pip python3-venv sudo && \
    rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN useradd -m kaliuser && echo 'kaliuser ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers
USER kaliuser
WORKDIR /home/kaliuser

# Set capabilities for nmap (if needed)
USER root
RUN setcap cap_net_raw,cap_net_admin,cap_net_bind_service+eip /usr/bin/nmap
USER kaliuser

# Copy MCP server code
COPY . /home/kaliuser/app
WORKDIR /home/kaliuser/app

# Create virtual environment and install Python dependencies
RUN python3 -m venv venv && \
    venv/bin/pip install --upgrade pip && \
    venv/bin/pip install -r requirements.txt

EXPOSE 8080
CMD ["./venv/bin/python", "main.py"]
