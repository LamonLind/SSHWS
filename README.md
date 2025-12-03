# SSHWS - One-Click VPN Installation Script

[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Version](https://img.shields.io/badge/version-1.0.0-green.svg)](https://github.com/LamonLind/SSHWS)
[![Platform](https://img.shields.io/badge/platform-Ubuntu%20%7C%20Debian-orange.svg)](https://github.com/LamonLind/SSHWS)

**Fully automated one-click installation script for SSH WebSocket, V2Ray (VLESS/VMESS), and XHTTP/SplitHTTP tunneling services with NGINX reverse proxy, automatic SSL, and Cloudflare CDN support.**

## 🚀 Features

### Services Included
- ✅ **SSH WebSocket (SSH-WS)** - WebSocket tunnel for SSH connections
- ✅ **V2Ray VMESS** - WebSocket protocol support
- ✅ **V2Ray VLESS** - Next-generation protocol
- ✅ **XHTTP/SplitHTTP** - Advanced HTTP tunneling
- ✅ **NGINX Reverse Proxy** - Optimized for WebSocket and HTTP/2
- ✅ **Automatic SSL** - Let's Encrypt with auto-renewal
- ✅ **Cloudflare CDN** - Full compatibility with Cloudflare proxy

### Port Configuration
- **80** - HTTP (auto-redirect to HTTPS)
- **443** - HTTPS with SSL/TLS
- **8080** - Alternative WebSocket port
- **8443** - Alternative HTTPS port
- **2087** - XHTTP service port

### Management Features
1. 📝 Create SSH-WS users
2. 👥 Create V2Ray users (VLESS/VMESS)
3. 🌐 Create XHTTP/SplitHTTP users
4. 🔧 Configure/Change domain
5. 🔐 Renew SSL certificates
6. ⚙️ Change service ports
7. ☁️ Enable/Disable Cloudflare CDN mode
8. 📋 List all users
9. 🗑️ Delete users
10. 📊 Show service status
11. 💾 Backup/Restore configuration
12. 🚄 Install BBR TCP optimization
13. 🛡️ Install Fail2Ban + Firewall rules
14. 📈 SpeedTest panel
15. 🔄 Update script
16. 🗂️ Uninstall everything

### Security Features
- 🔒 Automatic SSL/TLS with Let's Encrypt
- 🛡️ Firewall configuration (UFW)
- 🚫 Fail2Ban integration
- ✅ Port conflict detection
- ✅ Domain validation
- ✅ Auto-fix SSL issues
- ✅ Secure configuration file permissions

### Advanced Features
- 🔄 Auto-detect Cloudflare proxy ON/OFF
- ⚡ NGINX optimization (HTTP/2, WebSocket, TLS 1.3)
- 🚄 BBR TCP congestion control
- 🌍 Multi-domain support
- 📜 Logs viewer in menu
- 🔧 Auto-repair SSL
- 📤 Optional GitHub Gist backup using API token

## 📋 Requirements

### System Requirements
- **OS**: Ubuntu 18.04+ or Debian 9+
- **Architecture**: x64 (amd64)
- **RAM**: Minimum 512MB (1GB+ recommended)
- **Disk Space**: Minimum 1GB free space
- **Root Access**: Required

### Network Requirements
- Public IP address
- Domain name (required for SSL)
- Open ports: 80, 443, 8080, 8443

## 🛠️ Installation

### Quick Installation (One Command)

```bash
wget -O install.sh https://raw.githubusercontent.com/LamonLind/SSHWS/main/install.sh && chmod +x install.sh && ./install.sh
```

Or using curl:

```bash
curl -O https://raw.githubusercontent.com/LamonLind/SSHWS/main/install.sh && chmod +x install.sh && ./install.sh
```

### Step-by-Step Installation

1. **Download the script**
   ```bash
   wget https://raw.githubusercontent.com/LamonLind/SSHWS/main/install.sh
   ```

2. **Make it executable**
   ```bash
   chmod +x install.sh
   ```

3. **Run the installation**
   ```bash
   sudo ./install.sh
   ```

4. **Wait for completion** (typically 5-10 minutes)

## 🎯 Post-Installation Setup

### 1. Configure Domain

After installation, run the management menu:

```bash
sshws-menu
```

Select option **4** to configure your domain:
- Enter your domain name (e.g., `vpn.example.com`)
- The script will automatically configure NGINX and obtain SSL certificate
- Make sure your domain's A record points to your server's IP

### 2. Create Users

From the menu, select:
- Option **1** for SSH-WS users
- Option **2** for V2Ray users (VLESS/VMESS)
- Option **3** for XHTTP/SplitHTTP users

Each user creation will generate:
- Connection details
- Configuration files
- QR codes (for V2Ray)
- WebSocket payloads (for SSH-WS)

## 📱 Usage Examples

### SSH-WS Connection

**Connection Information:**
```
Host: your-domain.com
Port: 80, 443, 8080, or 8443
SSH Port: 22
WebSocket Path: /ssh-ws
```

**WebSocket Payload:**
```
GET /ssh-ws HTTP/1.1[crlf]
Host: your-domain.com[crlf]
Upgrade: websocket[crlf]
Connection: Upgrade[crlf][crlf]
```

**OpenSSH Command:**
```bash
ssh username@your-domain.com
```

### V2Ray VMESS

Configuration will be provided as:
- JSON configuration
- Connection link (vmess://)
- QR code for mobile apps

**Recommended Clients:**
- Windows: V2RayN
- Android: V2RayNG
- iOS: Shadowrocket
- macOS: V2RayU

### V2Ray VLESS

Similar to VMESS with:
- Connection link (vless://)
- QR code
- Support for latest V2Ray cores

### XHTTP/SplitHTTP

Advanced protocol for:
- Better performance over CDN
- Improved stealth capabilities
- Cloudflare optimization

## 🔧 Management Panel

Access the management panel anytime:

```bash
sshws-menu
```

### Main Menu Options

```
╔═══════════════════════════════════════════════════════╗
║           SSHWS Management Panel v1.0.0               ║
╚═══════════════════════════════════════════════════════╝

  User Management:
    1) Create SSH-WS User
    2) Create V2Ray User (VLESS/VMESS)
    3) Create XHTTP/SplitHTTP User
    8) List All Users
    9) Delete User

  Configuration:
    4) Configure/Change Domain
    5) Renew SSL Certificate
    6) Change Service Ports
    7) Toggle Cloudflare CDN Mode

  System:
    10) Show Service Status
    11) Backup/Restore Configuration
    12) Install BBR TCP Optimization
    13) Configure Fail2Ban + Firewall

  Maintenance:
    14) Run SpeedTest
    15) Update Script
    16) Uninstall Everything

    0) Exit
```

## ☁️ Cloudflare Integration

### Enable Cloudflare CDN

1. **In Cloudflare Dashboard:**
   - Add your domain
   - Point A record to your server IP
   - Enable proxy (orange cloud)
   - Set SSL/TLS mode to "Full (strict)"

2. **On Server:**
   - Run `sshws-menu`
   - Configuration is already Cloudflare-compatible
   - No additional setup needed

### Cloudflare Settings

**Recommended SSL/TLS Settings:**
- Encryption mode: **Full (strict)**
- Minimum TLS Version: **TLS 1.2**
- TLS 1.3: **Enabled**
- Automatic HTTPS Rewrites: **Enabled**

**Speed Optimization:**
- Auto Minify: **Enable all**
- Brotli: **Enabled**
- HTTP/2: **Enabled**
- HTTP/3 (QUIC): **Enabled**

## 🔐 Security Best Practices

### Firewall Configuration

The script automatically configures UFW firewall:

```bash
# Check firewall status
sudo ufw status

# Allow additional ports if needed
sudo ufw allow 2087/tcp
```

### Fail2Ban

Monitor and manage Fail2Ban:

```bash
# Check status
sudo fail2ban-client status

# Unban an IP
sudo fail2ban-client set sshd unbanip <IP>
```

### Regular Updates

Keep your system secure:

```bash
# Update system
sudo apt update && sudo apt upgrade -y

# Update script (from menu)
sshws-menu → Option 15
```

## 📊 Monitoring and Logs

### Service Status

```bash
# Check all services
systemctl status nginx sshws v2ray-vmess v2ray-vless xhttp

# Individual service
systemctl status nginx
```

### View Logs

```bash
# NGINX logs
tail -f /var/log/nginx/access.log
tail -f /var/log/nginx/error.log

# V2Ray logs
tail -f /var/log/v2ray/access.log
tail -f /var/log/v2ray/error.log

# SSHWS logs
journalctl -u sshws -f

# System logs
tail -f /var/log/sshws/system.log
```

### SpeedTest

Run from management menu (Option 14) or directly:

```bash
speedtest-cli --simple
```

## 💾 Backup and Restore

### Create Backup

From menu (Option 11) or manually:

```bash
# Backup all configurations
tar -czf backup_$(date +%Y%m%d).tar.gz \
    /var/lib/sshws \
    /etc/sshws \
    /etc/v2ray \
    /etc/xhttp \
    /etc/nginx/conf.d/sshws.conf
```

### Restore Backup

From menu (Option 11):
- Select restore option
- Choose backup file
- Services will be automatically restarted

## 🚄 BBR TCP Optimization

Enable BBR for better performance:

From menu:
```
Option 12 → Install BBR TCP Optimization
```

Or manually:
```bash
echo "net.core.default_qdisc=fq" | sudo tee -a /etc/sysctl.conf
echo "net.ipv4.tcp_congestion_control=bbr" | sudo tee -a /etc/sysctl.conf
sudo sysctl -p
```

Verify:
```bash
sysctl net.ipv4.tcp_congestion_control
# Should output: net.ipv4.tcp_congestion_control = bbr
```

## 🗑️ Uninstallation

### Complete Removal

From menu (Option 16) or manually:

```bash
# Stop all services
sudo systemctl stop nginx sshws v2ray-vmess v2ray-vless xhttp

# Remove configurations
sudo rm -rf /etc/sshws /etc/v2ray /etc/xhttp /var/lib/sshws

# Remove services
sudo rm -f /etc/systemd/system/sshws.service
sudo rm -f /etc/systemd/system/v2ray-vmess.service
sudo rm -f /etc/systemd/system/v2ray-vless.service
sudo rm -f /etc/systemd/system/xhttp.service

# Reload systemd
sudo systemctl daemon-reload
```

**Note:** NGINX, SSL certificates, and V2Ray binary are not removed automatically.

## 🐛 Troubleshooting

### Common Issues

**1. SSL Certificate Fails**
```bash
# Check if port 80 is open
sudo netstat -tuln | grep :80

# Make sure NGINX is running
sudo systemctl status nginx

# Manually obtain certificate using webroot method
sudo certbot certonly --webroot -w /var/www/html -d your-domain.com

# Reload NGINX
sudo systemctl reload nginx
```

**2. Service Not Starting**
```bash
# Check service status
sudo systemctl status sshws

# View detailed logs
sudo journalctl -u sshws -n 50

# Check port conflicts
sudo netstat -tuln | grep 10000
```

**3. Domain Not Resolving**
```bash
# Check DNS
nslookup your-domain.com

# Ping domain
ping your-domain.com

# Check NGINX configuration
sudo nginx -t
```

**4. Connection Refused**
```bash
# Check firewall
sudo ufw status

# Allow required ports
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp

# Check if services are listening
sudo netstat -tuln | grep -E ':(80|443|8080|8443)'
```

**5. WebSocket Not Working on Port 80**
```bash
# Check if NGINX is proxying WebSocket correctly
curl -i -N -H "Connection: Upgrade" -H "Upgrade: websocket" \
  http://your-domain.com/ssh-ws

# Verify NGINX configuration includes WebSocket on port 80
grep -A 10 "listen 80" /etc/nginx/conf.d/sshws.conf | grep "location /ssh-ws"

# Test V2Ray endpoint
curl -i http://your-domain.com/vmess

# Restart NGINX if needed
sudo systemctl restart nginx
```

**6. V2Ray Not Working Through NGINX**
```bash
# Check if V2Ray services are running
sudo systemctl status v2ray-vmess v2ray-vless xhttp

# Verify V2Ray is listening on internal ports
sudo netstat -tuln | grep -E ':(10001|10002|10003)'

# Check NGINX is forwarding to V2Ray
sudo tail -f /var/log/nginx/error.log

# Test WebSocket upgrade headers
curl -i -H "Upgrade: websocket" -H "Connection: Upgrade" \
  https://your-domain.com/vmess
```

### Getting Help

If you encounter issues:

1. Check logs in `/var/log/sshws/`
2. Run `sshws-menu` → Option 10 (Service Status)
3. Open an issue on [GitHub](https://github.com/LamonLind/SSHWS/issues)

## 📁 File Structure

```
/etc/sshws/          - SSH-WS configuration
/etc/v2ray/          - V2Ray configurations
/etc/xhttp/          - XHTTP configuration
/var/lib/sshws/      - User database and data
/var/log/sshws/      - Log files
/var/www/html/       - Web root for ACME challenge
```

### User Data

User configurations are saved in:
```
/var/lib/sshws/users/
├── username_ssh.txt      - SSH-WS account details
├── username_vmess.txt    - VMESS account details
├── username_vless.txt    - VLESS account details
├── username_xhttp.txt    - XHTTP account details
└── username_*_qr.txt     - QR codes
```

## 🔄 Updates

### Check for Updates

From menu (Option 15) or manually:

```bash
# Download latest version
wget -O /tmp/install.sh https://raw.githubusercontent.com/LamonLind/SSHWS/main/install.sh

# Compare versions
# If newer, backup and reinstall
```

### Changelog

**Version 1.0.0** (Initial Release)
- Complete installation script
- SSH-WS, V2Ray, XHTTP support
- NGINX reverse proxy
- Automatic SSL
- Cloudflare integration
- Management panel
- Backup/restore functionality

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## ⭐ Support

If you find this project useful, please consider:
- Giving it a ⭐ star on GitHub
- Sharing it with others
- Contributing to development

## 📞 Contact

- **GitHub Issues**: [Report bugs or request features](https://github.com/LamonLind/SSHWS/issues)
- **Discussions**: [Ask questions or share ideas](https://github.com/LamonLind/SSHWS/discussions)

## ⚠️ Disclaimer

This software is provided "as is" without warranty of any kind. Use at your own risk. The authors are not responsible for any misuse or damage caused by this software.

## 🙏 Acknowledgments

- [V2Ray Project](https://www.v2ray.com/)
- [NGINX](https://nginx.org/)
- [Let's Encrypt](https://letsencrypt.org/)
- [Cloudflare](https://www.cloudflare.com/)

---

**Made with ❤️ by the SSHWS Community**

*For support and updates, visit [GitHub Repository](https://github.com/LamonLind/SSHWS)*
