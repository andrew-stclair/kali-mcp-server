FROM kalilinux/kali-rolling

# Install required tools
RUN apt-get update && apt-get install -y \
    nmap nikto sqlmap wpscan dirb exploitdb python3 python3-pip sudo && \
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

# Install Python dependencies
RUN pip3 install -r requirements.txt

EXPOSE 8080
CMD ["python3", "main.py"]
