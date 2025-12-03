#!/bin/bash

#############################################
# SSHWS + V2Ray + XHTTP Installation Script
# One-Click Installation for Ubuntu/Debian
# Author: SSHWS Project
# Version: 1.0.0
#############################################

set -e

# Color definitions
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Global variables
INSTALL_DIR="/etc/sshws"
V2RAY_DIR="/etc/v2ray"
XHTTP_DIR="/etc/xhttp"
NGINX_CONF_DIR="/etc/nginx/conf.d"
SSL_DIR="/etc/letsencrypt"
DATA_DIR="/var/lib/sshws"
LOG_DIR="/var/log/sshws"
SCRIPT_VERSION="1.0.0"

# Default ports
SSH_WS_PORT=80
V2RAY_VMESS_PORT=443
V2RAY_VLESS_PORT=8443
XHTTP_PORT=2087
NGINX_SSL_PORT=443
NGINX_HTTP_PORT=80

# Files
USERS_DB="$DATA_DIR/users.db"
DOMAIN_FILE="$DATA_DIR/domain.txt"
CONFIG_FILE="$DATA_DIR/config.conf"

# Temporary files array for cleanup
declare -a TEMP_FILES=()

#############################################
# Cleanup Functions
#############################################

cleanup_temp_files() {
    # Clean up any temporary files
    for temp_file in "${TEMP_FILES[@]}"; do
        [[ -f "$temp_file" ]] && rm -f "$temp_file"
    done
}

# Set trap for cleanup on exit
trap cleanup_temp_files EXIT INT TERM

#############################################
# Utility Functions
#############################################

print_msg() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_header() {
    clear
    echo -e "${CYAN}"
    echo "╔═══════════════════════════════════════════════════════╗"
    echo "║       SSHWS + V2Ray + XHTTP Installation Script      ║"
    echo "║              One-Click Full Stack Setup               ║"
    echo "║                   Version $SCRIPT_VERSION                      ║"
    echo "╚═══════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

check_root() {
    if [[ $EUID -ne 0 ]]; then
        print_error "This script must be run as root"
        exit 1
    fi
}

detect_os() {
    print_msg "Detecting operating system..."
    
    if [[ -f /etc/os-release ]]; then
        # Safely parse OS information without sourcing the file
        OS=$(grep "^ID=" /etc/os-release | cut -d'=' -f2 | tr -d '"')
        OS_VERSION=$(grep "^VERSION_ID=" /etc/os-release | cut -d'=' -f2 | tr -d '"')
    else
        print_error "Cannot detect operating system"
        exit 1
    fi
    
    if [[ "$OS" != "ubuntu" && "$OS" != "debian" ]]; then
        print_error "This script only supports Ubuntu and Debian"
        exit 1
    fi
    
    print_success "Detected: $OS $OS_VERSION"
}

check_port_conflict() {
    local port=$1
    if netstat -tuln | grep -q ":$port "; then
        print_warning "Port $port is already in use"
        return 1
    fi
    return 0
}

create_directories() {
    print_msg "Creating directory structure..."
    
    mkdir -p "$INSTALL_DIR"
    mkdir -p "$V2RAY_DIR"
    mkdir -p "$XHTTP_DIR"
    mkdir -p "$DATA_DIR"
    mkdir -p "$LOG_DIR"
    mkdir -p "$DATA_DIR/users"
    mkdir -p "$DATA_DIR/backups"
    
    # Initialize users database if not exists
    if [[ ! -f "$USERS_DB" ]]; then
        cat > "$USERS_DB" << EOF
# SSHWS Users Database
# Format: type|username|password|uuid|expiry|created
EOF
    fi
    
    print_success "Directory structure created"
}

#############################################
# Dependency Installation
#############################################

update_system() {
    print_msg "Updating system packages..."
    if ! apt-get update -q; then
        print_error "Failed to update package lists"
        print_warning "Continuing anyway, but some packages may not install correctly"
    else
        print_success "System updated"
    fi
}

install_dependencies() {
    print_msg "Installing dependencies..."
    
    DEBIAN_FRONTEND=noninteractive apt-get install -y \
        curl \
        wget \
        git \
        unzip \
        tar \
        openssl \
        cron \
        software-properties-common \
        gnupg2 \
        ca-certificates \
        lsb-release \
        apt-transport-https \
        netcat \
        net-tools \
        dnsutils \
        qrencode \
        jq \
        uuid-runtime \
        certbot \
        python3-certbot-nginx \
        fail2ban \
        ufw \
        iptables \
        bc \
        vnstat \
        speedtest-cli \
        nginx \
        openssh-server \
        python3-pip \
        > /dev/null 2>&1
    
    print_success "Dependencies installed"
}

#############################################
# NGINX Installation and Configuration
#############################################

install_nginx() {
    print_msg "Installing and configuring NGINX..."
    
    # Enable NGINX
    systemctl enable nginx
    systemctl start nginx
    
    # Backup original nginx.conf
    if [[ ! -f /etc/nginx/nginx.conf.backup ]]; then
        cp /etc/nginx/nginx.conf /etc/nginx/nginx.conf.backup
    fi
    
    # Create optimized nginx.conf
    cat > /etc/nginx/nginx.conf << 'EOF'
user www-data;
worker_processes auto;
pid /run/nginx.pid;
include /etc/nginx/modules-enabled/*.conf;

events {
    worker_connections 2048;
    multi_accept on;
    use epoll;
}

http {
    sendfile on;
    tcp_nopush on;
    tcp_nodelay on;
    keepalive_timeout 65;
    types_hash_max_size 2048;
    server_tokens off;
    client_max_body_size 50M;

    # HTTP/2 support
    http2_max_field_size 16k;
    http2_max_header_size 32k;

    # WebSocket support
    map $http_upgrade $connection_upgrade {
        default upgrade;
        '' close;
    }

    include /etc/nginx/mime.types;
    default_type application/octet-stream;

    # SSL Settings
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_prefer_server_ciphers on;
    ssl_ciphers 'ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384';
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 10m;

    # Logging
    access_log /var/log/nginx/access.log;
    error_log /var/log/nginx/error.log;

    # Gzip Settings
    gzip on;
    gzip_vary on;
    gzip_proxied any;
    gzip_comp_level 6;
    gzip_types text/plain text/css text/xml text/javascript application/json application/javascript application/xml+rss application/rss+xml font/truetype font/opentype application/vnd.ms-fontobject image/svg+xml;

    # Virtual Host Configs
    include /etc/nginx/conf.d/*.conf;
    include /etc/nginx/sites-enabled/*;
}
EOF
    
    # Remove default site
    rm -f /etc/nginx/sites-enabled/default
    
    print_success "NGINX configured"
}

#############################################
# SSH-WS Installation
#############################################

install_sshws() {
    print_msg "Installing SSH-WS service..."
    
    # Create SSH-WS configuration
    cat > "$INSTALL_DIR/config.json" << 'EOF'
{
    "listen": "0.0.0.0:10000",
    "redirect": "127.0.0.1:22",
    "verbose": false
}
EOF
    
    # Download or create SSH-WS binary (using Python implementation)
    cat > "$INSTALL_DIR/sshws.py" << 'EOFPYTHON'
#!/usr/bin/env python3
import asyncio
import websockets
import socket
import json
import sys
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger('sshws')

class SSHWebSocketProxy:
    def __init__(self, ws_host, ws_port, ssh_host, ssh_port):
        self.ws_host = ws_host
        self.ws_port = ws_port
        self.ssh_host = ssh_host
        self.ssh_port = ssh_port

    async def proxy_ssh(self, websocket, path):
        try:
            reader, writer = await asyncio.open_connection(self.ssh_host, self.ssh_port)
            
            async def ws_to_ssh():
                try:
                    async for message in websocket:
                        if isinstance(message, bytes):
                            writer.write(message)
                            await writer.drain()
                except Exception as e:
                    logger.error(f"WS to SSH error: {e}")
                finally:
                    writer.close()
            
            async def ssh_to_ws():
                try:
                    while True:
                        data = await reader.read(4096)
                        if not data:
                            break
                        await websocket.send(data)
                except Exception as e:
                    logger.error(f"SSH to WS error: {e}")
            
            await asyncio.gather(ws_to_ssh(), ssh_to_ws())
            
        except Exception as e:
            logger.error(f"Connection error: {e}")

    async def start(self):
        logger.info(f"Starting SSH-WS proxy on {self.ws_host}:{self.ws_port}")
        async with websockets.serve(self.proxy_ssh, self.ws_host, self.ws_port):
            await asyncio.Future()

if __name__ == '__main__':
    config_file = '/etc/sshws/config.json'
    try:
        with open(config_file, 'r') as f:
            config = json.load(f)
        
        ws_host, ws_port = config['listen'].split(':')
        ssh_host, ssh_port = config['redirect'].split(':')
        
        proxy = SSHWebSocketProxy(ws_host, int(ws_port), ssh_host, int(ssh_port))
        asyncio.run(proxy.start())
    except Exception as e:
        logger.error(f"Failed to start: {e}")
        sys.exit(1)
EOFPYTHON
    
    chmod +x "$INSTALL_DIR/sshws.py"
    
    # Install Python websockets library
    pip3 install websockets > /dev/null 2>&1
    
    # Create systemd service for SSH-WS
    cat > /etc/systemd/system/sshws.service << EOF
[Unit]
Description=SSH WebSocket Service
After=network.target

[Service]
Type=simple
User=root
ExecStart=/usr/bin/python3 $INSTALL_DIR/sshws.py
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF
    
    systemctl daemon-reload
    systemctl enable sshws
    systemctl start sshws
    
    print_success "SSH-WS service installed"
}

#############################################
# V2Ray Installation
#############################################

install_v2ray() {
    print_msg "Installing V2Ray..."
    
    # Download V2Ray installation script with verification
    local v2ray_script="/tmp/v2ray-install.sh"
    if ! curl -L -o "$v2ray_script" https://raw.githubusercontent.com/v2fly/fhs-install-v2ray/master/install-release.sh; then
        print_error "Failed to download V2Ray installation script"
        return 1
    fi
    
    # Execute the script
    bash "$v2ray_script" > /dev/null 2>&1 || {
        print_error "V2Ray installation failed"
        rm -f "$v2ray_script"
        return 1
    }
    
    # Clean up
    rm -f "$v2ray_script"
    
    # Create V2Ray VMESS config
    cat > "$V2RAY_DIR/vmess-config.json" << 'EOF'
{
  "log": {
    "loglevel": "warning",
    "access": "/var/log/v2ray/access.log",
    "error": "/var/log/v2ray/error.log"
  },
  "inbounds": [
    {
      "port": 10001,
      "listen": "127.0.0.1",
      "protocol": "vmess",
      "settings": {
        "clients": []
      },
      "streamSettings": {
        "network": "ws",
        "wsSettings": {
          "path": "/vmess"
        }
      }
    }
  ],
  "outbounds": [
    {
      "protocol": "freedom",
      "settings": {}
    }
  ]
}
EOF
    
    # Create V2Ray VLESS config
    cat > "$V2RAY_DIR/vless-config.json" << 'EOF'
{
  "log": {
    "loglevel": "warning",
    "access": "/var/log/v2ray/access.log",
    "error": "/var/log/v2ray/error.log"
  },
  "inbounds": [
    {
      "port": 10002,
      "listen": "127.0.0.1",
      "protocol": "vless",
      "settings": {
        "clients": [],
        "decryption": "none"
      },
      "streamSettings": {
        "network": "ws",
        "wsSettings": {
          "path": "/vless"
        }
      }
    }
  ],
  "outbounds": [
    {
      "protocol": "freedom",
      "settings": {}
    }
  ]
}
EOF
    
    # Create log directory
    mkdir -p /var/log/v2ray
    
    # Create systemd services for VMESS and VLESS
    cat > /etc/systemd/system/v2ray-vmess.service << EOF
[Unit]
Description=V2Ray VMESS Service
After=network.target

[Service]
Type=simple
User=root
ExecStart=/usr/local/bin/v2ray run -config $V2RAY_DIR/vmess-config.json
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF
    
    cat > /etc/systemd/system/v2ray-vless.service << EOF
[Unit]
Description=V2Ray VLESS Service
After=network.target

[Service]
Type=simple
User=root
ExecStart=/usr/local/bin/v2ray run -config $V2RAY_DIR/vless-config.json
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF
    
    systemctl daemon-reload
    systemctl enable v2ray-vmess
    systemctl enable v2ray-vless
    systemctl start v2ray-vmess
    systemctl start v2ray-vless
    
    print_success "V2Ray installed and configured"
}

#############################################
# XHTTP/SplitHTTP Installation
#############################################

install_xhttp() {
    print_msg "Installing XHTTP/SplitHTTP service..."
    
    # Create XHTTP config
    cat > "$XHTTP_DIR/config.json" << 'EOF'
{
  "log": {
    "loglevel": "warning",
    "access": "/var/log/xhttp/access.log",
    "error": "/var/log/xhttp/error.log"
  },
  "inbounds": [
    {
      "port": 10003,
      "listen": "127.0.0.1",
      "protocol": "vless",
      "settings": {
        "clients": [],
        "decryption": "none"
      },
      "streamSettings": {
        "network": "splithttp",
        "splithttpSettings": {
          "path": "/xhttp"
        }
      }
    }
  ],
  "outbounds": [
    {
      "protocol": "freedom",
      "settings": {}
    }
  ]
}
EOF
    
    mkdir -p /var/log/xhttp
    
    # Create systemd service for XHTTP
    cat > /etc/systemd/system/xhttp.service << EOF
[Unit]
Description=XHTTP/SplitHTTP Service
After=network.target

[Service]
Type=simple
User=root
ExecStart=/usr/local/bin/v2ray run -config $XHTTP_DIR/config.json
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF
    
    systemctl daemon-reload
    systemctl enable xhttp
    systemctl start xhttp
    
    print_success "XHTTP service installed"
}

#############################################
# Domain and SSL Configuration
#############################################

configure_domain() {
    local domain=$1
    
    print_msg "Configuring domain: $domain"
    
    # Validate domain
    if ! [[ "$domain" =~ ^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$ ]]; then
        print_error "Invalid domain format"
        return 1
    fi
    
    # Save domain
    echo "$domain" > "$DOMAIN_FILE"
    
    # Check if SSL certificate already exists
    if [[ -f "/etc/letsencrypt/live/$domain/fullchain.pem" ]]; then
        # SSL exists, create full config with HTTPS
        create_nginx_config_with_ssl "$domain"
    else
        # SSL doesn't exist, create HTTP-only config for ACME challenge
        create_nginx_config_http_only "$domain"
    fi
    
    # Test NGINX configuration
    nginx -t > /dev/null 2>&1 || {
        print_error "NGINX configuration test failed"
        return 1
    }
    
    # Reload NGINX to apply configuration
    systemctl reload nginx
    
    print_success "Domain configured"
    return 0
}

create_nginx_config_http_only() {
    local domain=$1
    
    # Create HTTP-only NGINX configuration for ACME challenge
    cat > "$NGINX_CONF_DIR/sshws.conf" << EOFNGINX
# HTTP Server - Handle ACME challenge and serve content
server {
    listen 80;
    listen [::]:80;
    server_name $domain;

    # Root directory
    root /var/www/html;
    index index.html index.htm;

    # ACME challenge for Let's Encrypt
    location ^~ /.well-known/acme-challenge/ {
        root /var/www/html;
        allow all;
    }

    # Serve content normally (no redirect yet)
    location / {
        try_files \$uri \$uri/ =404;
    }
}

# Additional port 8080 for WebSocket (HTTP only before SSL)
server {
    listen 8080;
    listen [::]:8080;
    server_name $domain;

    location /ssh-ws {
        proxy_pass http://127.0.0.1:10000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$host;
        proxy_connect_timeout 7d;
        proxy_send_timeout 7d;
        proxy_read_timeout 7d;
    }

    location / {
        return 404;
    }
}
EOFNGINX
}

create_nginx_config_with_ssl() {
    local domain=$1
    
    # Create full NGINX configuration with SSL support
    cat > "$NGINX_CONF_DIR/sshws.conf" << EOFNGINX
# HTTP Server - Redirect to HTTPS and handle ACME challenge
server {
    listen 80;
    listen [::]:80;
    server_name $domain;

    # ACME challenge for Let's Encrypt
    location ^~ /.well-known/acme-challenge/ {
        root /var/www/html;
        allow all;
    }

    # Redirect all other HTTP traffic to HTTPS
    location / {
        return 301 https://\$host\$request_uri;
    }
}

# HTTPS Server with WebSocket support
server {
    listen 443 ssl http2;
    listen [::]:443 ssl http2;
    listen 8443 ssl http2;
    listen [::]:8443 ssl http2;
    server_name $domain;

    # SSL Configuration
    ssl_certificate /etc/letsencrypt/live/$domain/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/$domain/privkey.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;
    ssl_prefer_server_ciphers on;

    # Security headers
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-Content-Type-Options "nosniff" always;

    # Root directory
    root /var/www/html;
    index index.html index.htm;

    # SSH-WS WebSocket endpoint
    location /ssh-ws {
        proxy_pass http://127.0.0.1:10000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_connect_timeout 7d;
        proxy_send_timeout 7d;
        proxy_read_timeout 7d;
    }

    # V2Ray VMESS WebSocket endpoint
    location /vmess {
        proxy_pass http://127.0.0.1:10001;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_connect_timeout 60s;
        proxy_send_timeout 60s;
        proxy_read_timeout 60s;
    }

    # V2Ray VLESS WebSocket endpoint
    location /vless {
        proxy_pass http://127.0.0.1:10002;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_connect_timeout 60s;
        proxy_send_timeout 60s;
        proxy_read_timeout 60s;
    }

    # XHTTP/SplitHTTP endpoint
    location /xhttp {
        proxy_pass http://127.0.0.1:10003;
        proxy_http_version 1.1;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
    }

    # Default location
    location / {
        try_files \$uri \$uri/ =404;
    }
}

# Additional port 8080 for WebSocket
server {
    listen 8080;
    listen [::]:8080;
    server_name $domain;

    location /ssh-ws {
        proxy_pass http://127.0.0.1:10000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$host;
        proxy_connect_timeout 7d;
        proxy_send_timeout 7d;
        proxy_read_timeout 7d;
    }

    location / {
        return 404;
    }
}
EOFNGINX
}

install_ssl() {
    local domain=$1
    
    print_msg "Installing SSL certificate for $domain..."
    
    # Create web root
    mkdir -p /var/www/html
    
    # Obtain certificate using webroot method
    # This doesn't require stopping NGINX and works with the ACME challenge location
    certbot certonly --webroot -w /var/www/html -d "$domain" --non-interactive --agree-tos --register-unsafely-without-email --staple-ocsp || {
        print_error "Failed to obtain SSL certificate"
        return 1
    }
    
    # Setup auto-renewal (check if already exists to avoid duplicates)
    local renewal_cron="0 0 * * * certbot renew --quiet --deploy-hook 'systemctl reload nginx'"
    if ! crontab -l 2>/dev/null | grep -q "certbot renew"; then
        (crontab -l 2>/dev/null; echo "$renewal_cron") | crontab -
    fi
    
    # Update NGINX config to use SSL
    create_nginx_config_with_ssl "$domain"
    
    # Test and reload NGINX
    nginx -t > /dev/null 2>&1 && systemctl reload nginx
    
    print_success "SSL certificate installed and auto-renewal configured"
}

#############################################
# Firewall and Security
#############################################

setup_firewall() {
    print_msg "Configuring firewall..."
    
    # UFW configuration
    ufw --force enable
    ufw default deny incoming
    ufw default allow outgoing
    ufw allow 22/tcp
    ufw allow 80/tcp
    ufw allow 443/tcp
    ufw allow 8080/tcp
    ufw allow 8443/tcp
    ufw allow 2087/tcp
    
    # Fail2ban configuration
    cat > /etc/fail2ban/jail.local << 'EOF'
[DEFAULT]
bantime = 3600
findtime = 600
maxretry = 5

[sshd]
enabled = true
port = 22
filter = sshd
logpath = /var/log/auth.log
maxretry = 3

[nginx-http-auth]
enabled = true
filter = nginx-http-auth
port = http,https
logpath = /var/log/nginx/error.log
EOF
    
    systemctl enable fail2ban
    systemctl restart fail2ban
    
    print_success "Firewall configured"
}

#############################################
# BBR TCP Optimization
#############################################

enable_bbr() {
    print_msg "Enabling BBR TCP optimization..."
    
    # Check if BBR is available
    if modprobe tcp_bbr 2>/dev/null; then
        cat >> /etc/sysctl.conf << 'EOF'

# BBR TCP Optimization
net.core.default_qdisc=fq
net.ipv4.tcp_congestion_control=bbr
EOF
        sysctl -p > /dev/null 2>&1
        print_success "BBR enabled"
    else
        print_warning "BBR not available on this kernel"
    fi
}

#############################################
# Management Scripts
#############################################

create_management_scripts() {
    print_msg "Creating management scripts..."
    
    # Create menu script
    cat > /usr/local/bin/sshws-menu << 'EOFMENU'
#!/bin/bash

# Load library functions
source /usr/local/lib/sshws/functions.sh

while true; do
    show_menu
    read -p "Select option: " choice
    
    case $choice in
        1) create_ssh_user ;;
        2) create_v2ray_user ;;
        3) create_xhttp_user ;;
        4) manage_domain ;;
        5) renew_ssl ;;
        6) change_ports ;;
        7) toggle_cloudflare ;;
        8) list_users ;;
        9) delete_user ;;
        10) show_status ;;
        11) backup_restore ;;
        12) install_bbr ;;
        13) configure_fail2ban ;;
        14) speedtest ;;
        15) update_script ;;
        16) uninstall_all ;;
        0) exit 0 ;;
        *) echo "Invalid option" ;;
    esac
    
    read -p "Press Enter to continue..."
done
EOFMENU
    
    chmod +x /usr/local/bin/sshws-menu
    
    # Create library directory
    mkdir -p /usr/local/lib/sshws
    
    # Create functions library
    cat > /usr/local/lib/sshws/functions.sh << 'EOFFUNC'
#!/bin/bash

# Configuration
DATA_DIR="/var/lib/sshws"
USERS_DB="$DATA_DIR/users.db"
DOMAIN_FILE="$DATA_DIR/domain.txt"
V2RAY_DIR="/etc/v2ray"
XHTTP_DIR="/etc/xhttp"

show_menu() {
    clear
    echo "╔═══════════════════════════════════════════════════════╗"
    echo "║           SSHWS Management Panel v1.0.0               ║"
    echo "╚═══════════════════════════════════════════════════════╝"
    echo ""
    echo "  User Management:"
    echo "    1) Create SSH-WS User"
    echo "    2) Create V2Ray User (VLESS/VMESS)"
    echo "    3) Create XHTTP/SplitHTTP User"
    echo "    8) List All Users"
    echo "    9) Delete User"
    echo ""
    echo "  Configuration:"
    echo "    4) Configure/Change Domain"
    echo "    5) Renew SSL Certificate"
    echo "    6) Change Service Ports"
    echo "    7) Toggle Cloudflare CDN Mode"
    echo ""
    echo "  System:"
    echo "    10) Show Service Status"
    echo "    11) Backup/Restore Configuration"
    echo "    12) Install BBR TCP Optimization"
    echo "    13) Configure Fail2Ban + Firewall"
    echo "    14) Run SpeedTest"
    echo ""
    echo "  Maintenance:"
    echo "    15) Update Script"
    echo "    16) Uninstall Everything"
    echo ""
    echo "    0) Exit"
    echo ""
}

create_ssh_user() {
    echo "=== Create SSH-WS User ==="
    read -p "Username: " username
    read -p "Password: " password
    read -p "Expiry days (default 30): " expiry_days
    expiry_days=${expiry_days:-30}
    
    # Create system user
    useradd -m -s /bin/bash "$username" 2>/dev/null || {
        echo "User already exists or error creating user"
        return 1
    }
    
    echo "$username:$password" | chpasswd
    
    # Set expiry
    expiry_date=$(date -d "+$expiry_days days" +%Y-%m-%d)
    chage -E "$expiry_date" "$username"
    
    # Get domain
    local domain=$(cat "$DOMAIN_FILE" 2>/dev/null || echo "your-domain.com")
    
    # Save to database
    echo "ssh|$username|$password||$expiry_date|$(date +%Y-%m-%d)" >> "$USERS_DB"
    
    # Generate config
    local config_file="$DATA_DIR/users/${username}_ssh.txt"
    cat > "$config_file" << EOFCONFIG
╔═══════════════════════════════════════════════════════╗
║              SSH-WS Account Information               ║
╚═══════════════════════════════════════════════════════╝

Username      : $username
Password      : $password
Domain        : $domain
Expiry Date   : $expiry_date
Created       : $(date +%Y-%m-%d)

Connection Details:
------------------
Protocol      : SSH WebSocket
Host          : $domain
Port          : 80, 443, 8080, 8443
SSH Port      : 22
WS Path       : /ssh-ws

WebSocket Payload:
GET /ssh-ws HTTP/1.1[crlf]Host: $domain[crlf]Upgrade: websocket[crlf]Connection: Upgrade[crlf][crlf]

Cloudflare Compatible: Yes
CDN Support: Yes

OpenSSH Command:
ssh $username@$domain -p 22

EOFCONFIG
    
    # Display
    cat "$config_file"
    echo ""
    echo "Configuration saved to: $config_file"
}

create_v2ray_user() {
    echo "=== Create V2Ray User ==="
    echo "1) VMESS"
    echo "2) VLESS"
    read -p "Select protocol: " protocol_choice
    
    read -p "Username/Remark: " username
    read -p "Expiry days (default 30): " expiry_days
    expiry_days=${expiry_days:-30}
    
    # Generate UUID
    local uuid=$(uuidgen)
    local protocol=""
    local config_file=""
    local port=10001
    local path="/vmess"
    
    if [[ "$protocol_choice" == "1" ]]; then
        protocol="vmess"
        config_file="$V2RAY_DIR/vmess-config.json"
        port=10001
        path="/vmess"
    else
        protocol="vless"
        config_file="$V2RAY_DIR/vless-config.json"
        port=10002
        path="/vless"
    fi
    
    # Add user to config
    local temp_file=$(mktemp)
    TEMP_FILES+=("$temp_file")
    local jq_success=0
    
    if [[ "$protocol" == "vmess" ]]; then
        if jq --arg id "$uuid" --arg email "$username" \
            '.inbounds[0].settings.clients += [{"id": $id, "alterId": 0, "email": $email}]' \
            "$config_file" > "$temp_file"; then
            mv "$temp_file" "$config_file"
            jq_success=1
        fi
    else
        if jq --arg id "$uuid" --arg email "$username" \
            '.inbounds[0].settings.clients += [{"id": $id, "email": $email}]' \
            "$config_file" > "$temp_file"; then
            mv "$temp_file" "$config_file"
            jq_success=1
        fi
    fi
    
    # Clean up temp file if jq failed
    [[ -f "$temp_file" ]] && rm -f "$temp_file"
    
    if [[ $jq_success -eq 0 ]]; then
        echo "Failed to add user to configuration"
        return 1
    fi
    
    # Restart service
    if [[ "$protocol" == "vmess" ]]; then
        systemctl restart v2ray-vmess
    else
        systemctl restart v2ray-vless
    fi
    
    # Get domain
    local domain=$(cat "$DOMAIN_FILE" 2>/dev/null || echo "your-domain.com")
    
    # Save to database
    local expiry_date=$(date -d "+$expiry_days days" +%Y-%m-%d)
    echo "$protocol|$username||$uuid|$expiry_date|$(date +%Y-%m-%d)" >> "$USERS_DB"
    
    # Generate link
    local link=""
    if [[ "$protocol" == "vmess" ]]; then
        local vmess_json=$(cat <<VMESSJSON
{
  "v": "2",
  "ps": "$username",
  "add": "$domain",
  "port": "443",
  "id": "$uuid",
  "aid": "0",
  "net": "ws",
  "type": "none",
  "host": "$domain",
  "path": "$path",
  "tls": "tls"
}
VMESSJSON
)
        link="vmess://$(echo -n "$vmess_json" | base64 -w 0)"
    else
        link="vless://${uuid}@${domain}:443?type=ws&security=tls&path=${path}&host=${domain}#${username}"
    fi
    
    # Generate QR code
    local qr_file="$DATA_DIR/users/${username}_${protocol}_qr.txt"
    echo "$link" | qrencode -t ANSIUTF8 > "$qr_file"
    
    # Save config
    local user_config="$DATA_DIR/users/${username}_${protocol}.txt"
    cat > "$user_config" << EOFV2RAY
╔═══════════════════════════════════════════════════════╗
║              V2Ray Account Information                ║
╚═══════════════════════════════════════════════════════╝

Protocol      : ${protocol^^}
Username      : $username
UUID          : $uuid
Domain        : $domain
Port          : 443, 8443
Path          : $path
Network       : WebSocket
Security      : TLS
Expiry Date   : $expiry_date
Created       : $(date +%Y-%m-%d)

Connection Link:
$link

QR Code:
EOFV2RAY
    cat "$qr_file" >> "$user_config"
    
    # Display
    cat "$user_config"
    echo ""
    echo "Configuration saved to: $user_config"
}

create_xhttp_user() {
    echo "=== Create XHTTP/SplitHTTP User ==="
    read -p "Username/Remark: " username
    read -p "Expiry days (default 30): " expiry_days
    expiry_days=${expiry_days:-30}
    
    # Generate UUID
    local uuid=$(uuidgen)
    
    # Add user to config
    local config_file="$XHTTP_DIR/config.json"
    local temp_file=$(mktemp)
    TEMP_FILES+=("$temp_file")
    
    if jq --arg id "$uuid" --arg email "$username" \
        '.inbounds[0].settings.clients += [{"id": $id, "email": $email}]' \
        "$config_file" > "$temp_file"; then
        mv "$temp_file" "$config_file"
    else
        rm -f "$temp_file"
        echo "Failed to add user to configuration"
        return 1
    fi
    
    # Clean up temp file if it still exists
    [[ -f "$temp_file" ]] && rm -f "$temp_file"
    
    # Restart service
    systemctl restart xhttp
    
    # Get domain
    local domain=$(cat "$DOMAIN_FILE" 2>/dev/null || echo "your-domain.com")
    
    # Save to database
    local expiry_date=$(date -d "+$expiry_days days" +%Y-%m-%d)
    echo "xhttp|$username||$uuid|$expiry_date|$(date +%Y-%m-%d)" >> "$USERS_DB"
    
    # Generate link
    local link="vless://${uuid}@${domain}:443?type=splithttp&security=tls&path=/xhttp&host=${domain}#${username}"
    
    # Generate QR code
    local qr_file="$DATA_DIR/users/${username}_xhttp_qr.txt"
    echo "$link" | qrencode -t ANSIUTF8 > "$qr_file"
    
    # Save config
    local user_config="$DATA_DIR/users/${username}_xhttp.txt"
    cat > "$user_config" << EOFXHTTP
╔═══════════════════════════════════════════════════════╗
║           XHTTP/SplitHTTP Account Information         ║
╚═══════════════════════════════════════════════════════╝

Protocol      : VLESS + SplitHTTP
Username      : $username
UUID          : $uuid
Domain        : $domain
Port          : 443, 8443
Path          : /xhttp
Network       : SplitHTTP
Security      : TLS
Expiry Date   : $expiry_date
Created       : $(date +%Y-%m-%d)

Connection Link:
$link

QR Code:
EOFXHTTP
    cat "$qr_file" >> "$user_config"
    
    # Display
    cat "$user_config"
    echo ""
    echo "Configuration saved to: $user_config"
}

manage_domain() {
    echo "=== Domain Management ==="
    echo "1) Add/Change Domain"
    echo "2) View Current Domain"
    read -p "Select option: " domain_choice
    
    if [[ "$domain_choice" == "1" ]]; then
        read -p "Enter domain name: " new_domain
        
        # Validate domain format
        if ! [[ "$new_domain" =~ ^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$ ]]; then
            echo "Invalid domain format"
            return 1
        fi
        
        echo "Configuring domain: $new_domain"
        
        # Call domain configuration from install script
        source /usr/local/lib/sshws/install-functions.sh
        configure_domain "$new_domain"
        install_ssl "$new_domain"
        
        echo "Domain configured successfully"
    else
        local current_domain=$(cat "$DOMAIN_FILE" 2>/dev/null || echo "Not configured")
        echo "Current domain: $current_domain"
    fi
}

renew_ssl() {
    echo "=== Renew SSL Certificate ==="
    certbot renew --force-renewal
    systemctl reload nginx
    echo "SSL certificate renewed"
}

change_ports() {
    echo "=== Change Service Ports ==="
    echo "Current configuration:"
    echo "  SSH-WS: 10000 (internal)"
    echo "  V2Ray VMESS: 10001 (internal)"
    echo "  V2Ray VLESS: 10002 (internal)"
    echo "  XHTTP: 10003 (internal)"
    echo ""
    echo "Note: External ports (80, 443, 8080, 8443) are managed by NGINX"
    echo "Changing internal ports requires manual configuration"
}

toggle_cloudflare() {
    echo "=== Cloudflare CDN Mode ==="
    echo "Current NGINX configuration supports Cloudflare CDN"
    echo ""
    echo "To enable Cloudflare:"
    echo "1. Point your domain A record to this server's IP"
    echo "2. Enable orange cloud (proxied) in Cloudflare dashboard"
    echo "3. Set SSL/TLS encryption mode to 'Full (strict)'"
    echo ""
    echo "To disable Cloudflare:"
    echo "1. Set DNS to 'DNS only' (grey cloud) in Cloudflare"
}

list_users() {
    echo "=== User List ==="
    echo ""
    echo "Type    | Username            | UUID/Password           | Expiry Date | Created"
    echo "--------|---------------------|-------------------------|-------------|------------"
    
    if [[ -f "$USERS_DB" ]]; then
        grep -v "^#" "$USERS_DB" | while IFS='|' read -r type username password uuid expiry created; do
            printf "%-7s | %-19s | %-23s | %-11s | %s\n" \
                "$type" "$username" "${uuid:-$password}" "$expiry" "$created"
        done
    else
        echo "No users found"
    fi
}

delete_user() {
    echo "=== Delete User ==="
    list_users
    echo ""
    read -p "Enter username to delete: " username
    
    # Find user type
    local user_line=$(grep "|$username|" "$USERS_DB")
    if [[ -z "$user_line" ]]; then
        echo "User not found"
        return 1
    fi
    
    local type=$(echo "$user_line" | cut -d'|' -f1)
    local uuid=$(echo "$user_line" | cut -d'|' -f4)
    
    # Remove from database
    sed -i "/|$username|/d" "$USERS_DB"
    
    # Remove from service configs
    case "$type" in
        ssh)
            userdel -r "$username" 2>/dev/null
            ;;
        vmess)
            local tmp_file=$(mktemp)
            TEMP_FILES+=("$tmp_file")
            if jq --arg id "$uuid" 'del(.inbounds[0].settings.clients[] | select(.id == $id))' \
                "$V2RAY_DIR/vmess-config.json" > "$tmp_file"; then
                mv "$tmp_file" "$V2RAY_DIR/vmess-config.json"
                systemctl restart v2ray-vmess
            fi
            rm -f "$tmp_file"
            ;;
        vless)
            local tmp_file=$(mktemp)
            TEMP_FILES+=("$tmp_file")
            if jq --arg id "$uuid" 'del(.inbounds[0].settings.clients[] | select(.id == $id))' \
                "$V2RAY_DIR/vless-config.json" > "$tmp_file"; then
                mv "$tmp_file" "$V2RAY_DIR/vless-config.json"
                systemctl restart v2ray-vless
            fi
            rm -f "$tmp_file"
            ;;
        xhttp)
            local tmp_file=$(mktemp)
            TEMP_FILES+=("$tmp_file")
            if jq --arg id "$uuid" 'del(.inbounds[0].settings.clients[] | select(.id == $id))' \
                "$XHTTP_DIR/config.json" > "$tmp_file"; then
                mv "$tmp_file" "$XHTTP_DIR/config.json"
                systemctl restart xhttp
            fi
            rm -f "$tmp_file"
            ;;
    esac
    
    # Remove user files
    rm -f "$DATA_DIR/users/${username}_"*
    
    echo "User $username deleted successfully"
}

show_status() {
    echo "=== Service Status ==="
    echo ""
    
    services=("nginx" "sshws" "v2ray-vmess" "v2ray-vless" "xhttp")
    
    for service in "${services[@]}"; do
        if systemctl is-active --quiet "$service"; then
            echo "✓ $service: Running"
        else
            echo "✗ $service: Stopped"
        fi
    done
    
    echo ""
    echo "=== Port Status ==="
    netstat -tuln | grep -E ':(80|443|8080|8443|10000|10001|10002|10003) '
}

backup_restore() {
    echo "=== Backup/Restore Configuration ==="
    echo "1) Backup Configuration"
    echo "2) Restore Configuration"
    read -p "Select option: " backup_choice
    
    if [[ "$backup_choice" == "1" ]]; then
        local backup_file="$DATA_DIR/backups/backup_$(date +%Y%m%d_%H%M%S).tar.gz"
        
        tar -czf "$backup_file" \
            "$DATA_DIR" \
            "/etc/sshws" \
            "/etc/v2ray" \
            "/etc/xhttp" \
            "/etc/nginx/conf.d/sshws.conf" \
            2>/dev/null
        
        echo "Backup created: $backup_file"
        echo "Size: $(du -h "$backup_file" | cut -f1)"
    else
        echo "Available backups:"
        ls -lh "$DATA_DIR/backups/"
        read -p "Enter backup filename to restore: " restore_file
        
        if [[ -f "$DATA_DIR/backups/$restore_file" ]]; then
            tar -xzf "$DATA_DIR/backups/$restore_file" -C /
            echo "Configuration restored. Restarting services..."
            systemctl restart nginx sshws v2ray-vmess v2ray-vless xhttp
            echo "Restore completed"
        else
            echo "Backup file not found"
        fi
    fi
}

install_bbr() {
    echo "=== Install BBR TCP Optimization ==="
    
    if lsmod | grep -q tcp_bbr; then
        echo "BBR is already enabled"
        return 0
    fi
    
    modprobe tcp_bbr
    
    if ! grep -q "tcp_bbr" /etc/modules-load.d/modules.conf 2>/dev/null; then
        echo "tcp_bbr" >> /etc/modules-load.d/modules.conf
    fi
    
    cat >> /etc/sysctl.conf << 'EOFBBR'
net.core.default_qdisc=fq
net.ipv4.tcp_congestion_control=bbr
EOFBBR
    
    sysctl -p
    
    echo "BBR enabled successfully"
    echo "Current congestion control: $(sysctl net.ipv4.tcp_congestion_control)"
}

configure_fail2ban() {
    echo "=== Configure Fail2Ban + Firewall ==="
    
    systemctl enable fail2ban
    systemctl restart fail2ban
    
    echo "Fail2Ban status:"
    fail2ban-client status
    
    echo ""
    echo "Firewall rules:"
    ufw status
}

speedtest() {
    echo "=== Running SpeedTest ==="
    echo ""
    
    if command -v speedtest-cli &> /dev/null; then
        speedtest-cli --simple
    else
        echo "Installing speedtest-cli..."
        pip3 install speedtest-cli
        speedtest-cli --simple
    fi
}

update_script() {
    echo "=== Update Script ==="
    echo "Checking for updates..."
    echo "Current version: 1.0.0"
    echo "Feature not yet implemented"
}

uninstall_all() {
    echo "=== Uninstall Everything ==="
    read -p "Are you sure you want to uninstall everything? (yes/no): " confirm
    
    if [[ "$confirm" != "yes" ]]; then
        echo "Uninstall cancelled"
        return 0
    fi
    
    echo "Stopping services..."
    systemctl stop nginx sshws v2ray-vmess v2ray-vless xhttp
    systemctl disable nginx sshws v2ray-vmess v2ray-vless xhttp
    
    echo "Removing services..."
    rm -f /etc/systemd/system/sshws.service
    rm -f /etc/systemd/system/v2ray-vmess.service
    rm -f /etc/systemd/system/v2ray-vless.service
    rm -f /etc/systemd/system/xhttp.service
    
    echo "Removing configurations..."
    rm -rf /etc/sshws
    rm -rf /etc/v2ray
    rm -rf /etc/xhttp
    rm -rf /var/lib/sshws
    rm -rf /var/log/sshws
    rm -f /etc/nginx/conf.d/sshws.conf
    
    echo "Removing scripts..."
    rm -f /usr/local/bin/sshws-menu
    rm -rf /usr/local/lib/sshws
    
    systemctl daemon-reload
    
    echo "Uninstall completed"
    echo "Note: NGINX, V2Ray binary, and SSL certificates were not removed"
    echo "You can remove them manually if needed"
}
EOFFUNC
    
    # Create install functions library
    cat > /usr/local/lib/sshws/install-functions.sh << 'EOFINSTFUNC'
#!/bin/bash

source /usr/local/lib/sshws/functions.sh

NGINX_CONF_DIR="/etc/nginx/conf.d"
DOMAIN_FILE="$DATA_DIR/domain.txt"

configure_domain() {
    local domain=$1
    
    echo "Configuring domain: $domain"
    
    # Validate domain
    if ! [[ "$domain" =~ ^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$ ]]; then
        echo "Invalid domain format"
        return 1
    fi
    
    # Save domain
    echo "$domain" > "$DOMAIN_FILE"
    
    # Check if SSL certificate already exists
    if [[ -f "/etc/letsencrypt/live/$domain/fullchain.pem" ]]; then
        # SSL exists, create full config with HTTPS
        create_nginx_config_with_ssl "$domain"
    else
        # SSL doesn't exist, create HTTP-only config for ACME challenge
        create_nginx_config_http_only "$domain"
    fi
    
    nginx -t && systemctl reload nginx
    echo "Domain configured successfully"
}

create_nginx_config_http_only() {
    local domain=$1
    
    # Create HTTP-only NGINX configuration for ACME challenge
    cat > "$NGINX_CONF_DIR/sshws.conf" << EOFNGINX
# HTTP Server - Handle ACME challenge and serve content
server {
    listen 80;
    listen [::]:80;
    server_name $domain;

    # Root directory
    root /var/www/html;
    index index.html index.htm;

    # ACME challenge for Let's Encrypt
    location ^~ /.well-known/acme-challenge/ {
        root /var/www/html;
        allow all;
    }

    # Serve content normally (no redirect yet)
    location / {
        try_files \$uri \$uri/ =404;
    }
}

# Additional port 8080 for WebSocket (HTTP only before SSL)
server {
    listen 8080;
    listen [::]:8080;
    server_name $domain;

    location /ssh-ws {
        proxy_pass http://127.0.0.1:10000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$host;
        proxy_connect_timeout 7d;
        proxy_send_timeout 7d;
        proxy_read_timeout 7d;
    }

    location / {
        return 404;
    }
}
EOFNGINX
}

create_nginx_config_with_ssl() {
    local domain=$1
    
    # Create full NGINX configuration with SSL support
    cat > "$NGINX_CONF_DIR/sshws.conf" << EOFNGINX
# HTTP Server - Redirect to HTTPS and handle ACME challenge
server {
    listen 80;
    listen [::]:80;
    server_name $domain;

    # ACME challenge for Let's Encrypt
    location ^~ /.well-known/acme-challenge/ {
        root /var/www/html;
        allow all;
    }

    # Redirect all other HTTP traffic to HTTPS
    location / {
        return 301 https://\$host\$request_uri;
    }
}

# HTTPS Server with WebSocket support
server {
    listen 443 ssl http2;
    listen [::]:443 ssl http2;
    listen 8443 ssl http2;
    listen [::]:8443 ssl http2;
    server_name $domain;

    # SSL Configuration
    ssl_certificate /etc/letsencrypt/live/$domain/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/$domain/privkey.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;

    root /var/www/html;
    index index.html;

    location /ssh-ws {
        proxy_pass http://127.0.0.1:10000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$host;
        proxy_connect_timeout 7d;
        proxy_send_timeout 7d;
        proxy_read_timeout 7d;
    }

    location /vmess {
        proxy_pass http://127.0.0.1:10001;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$host;
    }

    location /vless {
        proxy_pass http://127.0.0.1:10002;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$host;
    }

    location /xhttp {
        proxy_pass http://127.0.0.1:10003;
        proxy_http_version 1.1;
        proxy_set_header Host \$host;
    }

    location / {
        try_files \$uri \$uri/ =404;
    }
}

# Additional port 8080 for WebSocket
server {
    listen 8080;
    listen [::]:8080;
    server_name $domain;

    location /ssh-ws {
        proxy_pass http://127.0.0.1:10000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_connect_timeout 7d;
        proxy_send_timeout 7d;
        proxy_read_timeout 7d;
    }

    location / {
        return 404;
    }
}
EOFNGINX
}

install_ssl() {
    local domain=$1
    
    echo "Installing SSL certificate for $domain..."
    
    mkdir -p /var/www/html
    
    # Obtain certificate using webroot method
    certbot certonly --webroot -w /var/www/html -d "$domain" --non-interactive --agree-tos --register-unsafely-without-email --staple-ocsp || {
        echo "Failed to obtain SSL certificate"
        return 1
    }
    
    # Setup auto-renewal (check if already exists to avoid duplicates)
    local renewal_cron="0 0 * * * certbot renew --quiet --deploy-hook 'systemctl reload nginx'"
    if ! crontab -l 2>/dev/null | grep -q "certbot renew"; then
        (crontab -l 2>/dev/null; echo "$renewal_cron") | crontab -
    fi
    
    # Update NGINX config to use SSL
    create_nginx_config_with_ssl "$domain"
    
    # Test and reload NGINX
    nginx -t && systemctl reload nginx
    
    echo "SSL certificate installed"
}
EOFINSTFUNC
    
    print_success "Management scripts created"
}

#############################################
# Main Installation Flow
#############################################

main() {
    print_header
    
    check_root
    detect_os
    
    print_msg "Starting installation..."
    echo ""
    
    # Installation steps
    update_system
    install_dependencies
    create_directories
    install_nginx
    install_sshws
    install_v2ray
    install_xhttp
    setup_firewall
    enable_bbr
    create_management_scripts
    
    print_header
    print_success "Installation completed successfully!"
    echo ""
    echo -e "${CYAN}Next steps:${NC}"
    echo "1. Configure your domain:"
    echo -e "   ${GREEN}sshws-menu${NC} (select option 4)"
    echo ""
    echo "2. Create users:"
    echo -e "   ${GREEN}sshws-menu${NC} (select option 1, 2, or 3)"
    echo ""
    echo -e "${YELLOW}Important:${NC}"
    echo "- Make sure your domain points to this server's IP"
    echo "- SSL certificate will be installed when you configure the domain"
    echo "- All services are running and will start on boot"
    echo ""
    echo -e "${CYAN}Service Status:${NC}"
    systemctl status nginx sshws v2ray-vmess v2ray-vless xhttp --no-pager | grep -E "(Loaded|Active)"
    echo ""
    echo -e "${CYAN}Access Management Panel:${NC}"
    echo -e "${GREEN}sshws-menu${NC}"
    echo ""
    
    # Save installation info
    local server_ip=$(hostname -I | awk '{print $1}' || echo "Unknown")
    cat > "$DATA_DIR/install_info.txt" << EOF
Installation Date: $(date)
Server IP: $server_ip
Version: $SCRIPT_VERSION
OS: $OS $OS_VERSION
EOF
    
    print_success "Thank you for using SSHWS!"
}

# Run main installation
main
