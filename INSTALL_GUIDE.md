# SSHWS Installation Guide

## Quick Installation

```bash
# Download and run the installation script
wget -O install.sh https://raw.githubusercontent.com/LamonLind/SSHWS/main/install.sh
chmod +x install.sh
sudo ./install.sh
```

## What Gets Installed

### Services
- **SSH WebSocket (SSH-WS)**: Port 10000 (internal)
- **V2Ray VMESS**: Port 10001 (internal)
- **V2Ray VLESS**: Port 10002 (internal)
- **XHTTP/SplitHTTP**: Port 10003 (internal)
- **NGINX**: Ports 80, 443, 8080, 8443 (external)

### Components
- NGINX reverse proxy with WebSocket optimization
- SSL/TLS certificates via Let's Encrypt
- UFW firewall with proper rules
- Fail2Ban for security
- BBR TCP optimization (optional)
- Systemd services for auto-start

### Management Tools
- Interactive menu system (`sshws-menu`)
- User creation and management
- Domain configuration
- SSL certificate management
- Backup/restore functionality

## Post-Installation Steps

### 1. Access Management Panel

```bash
sudo sshws-menu
```

### 2. Configure Domain (Required for SSL)

From the menu, select option **4**:
- Enter your domain name (e.g., vpn.example.com)
- Ensure DNS points to your server IP
- SSL certificate will be obtained automatically

### 3. Create Users

Choose from:
- **Option 1**: SSH-WS users
- **Option 2**: V2Ray users (VMESS/VLESS)
- **Option 3**: XHTTP users

Each user creation generates:
- Connection details
- Configuration files (saved in `/var/lib/sshws/users/`)
- QR codes for V2Ray users

## Testing Installation

Run the test script to verify everything is working:

```bash
sudo bash test-installation.sh
```

This will check:
- Directory structure
- Configuration files
- Service status
- Port listening
- Firewall rules
- And more...

## Directory Structure

```
/etc/sshws/          # SSH-WS configuration
/etc/v2ray/          # V2Ray configurations
/etc/xhttp/          # XHTTP configuration
/var/lib/sshws/      # User database and data
  ├── users/         # User configuration files
  └── backups/       # Backup files
/var/log/sshws/      # Log files
```

## Common Commands

### Service Management
```bash
# Check service status
sudo systemctl status sshws
sudo systemctl status v2ray-vmess
sudo systemctl status v2ray-vless
sudo systemctl status xhttp
sudo systemctl status nginx

# Restart services
sudo systemctl restart nginx
sudo systemctl restart sshws

# View logs
sudo journalctl -u sshws -f
sudo tail -f /var/log/nginx/error.log
```

### Firewall
```bash
# Check firewall status
sudo ufw status

# Allow additional ports
sudo ufw allow 2087/tcp
```

### SSL Certificates
```bash
# List certificates
sudo certbot certificates

# Renew manually
sudo certbot renew

# Check renewal timer
sudo systemctl status certbot.timer
```

## Cloudflare Setup

### 1. In Cloudflare Dashboard
- Add your domain
- Create an A record pointing to your server IP
- Enable proxy (orange cloud icon)
- Set SSL/TLS mode to **"Full (strict)"**

### 2. SSL/TLS Settings
- Minimum TLS Version: TLS 1.2
- TLS 1.3: Enabled
- Automatic HTTPS Rewrites: Enabled

### 3. Speed Settings
- Auto Minify: Enable all
- Brotli: Enabled
- HTTP/2: Enabled
- HTTP/3 (QUIC): Enabled

## Troubleshooting

### Installation Failed
```bash
# Check logs
sudo tail -f /var/log/syslog

# Verify system requirements
df -h          # Check disk space
free -h        # Check memory
uname -a       # Check OS version
```

### Services Not Starting
```bash
# Check service logs
sudo journalctl -u sshws -n 50

# Check port conflicts
sudo ss -tuln | grep -E ':(80|443|10000|10001|10002|10003)'

# Restart services
sudo systemctl restart nginx sshws v2ray-vmess v2ray-vless xhttp
```

### SSL Certificate Issues
```bash
# Check if port 80 is accessible
curl -I http://your-domain.com

# Manual certificate request
sudo certbot certonly --standalone -d your-domain.com

# Check certificate status
sudo certbot certificates
```

### Connection Issues
```bash
# Verify NGINX configuration
sudo nginx -t

# Check if services are running
sudo systemctl status nginx sshws v2ray-vmess v2ray-vless xhttp

# Check firewall
sudo ufw status
```

## User Management

### Create SSH-WS User
```bash
sshws-menu → Option 1
# Enter username, password, and expiry days
# Configuration will be saved to /var/lib/sshws/users/
```

### Create V2Ray User
```bash
sshws-menu → Option 2
# Select VMESS or VLESS
# Enter username and expiry days
# QR code will be generated automatically
```

### List Users
```bash
sshws-menu → Option 8
# Shows all users with expiry dates
```

### Delete User
```bash
sshws-menu → Option 9
# Enter username to delete
# User will be removed from all services
```

## Backup and Restore

### Create Backup
```bash
sshws-menu → Option 11 → Option 1
# Backup saved to /var/lib/sshws/backups/
```

### Restore Backup
```bash
sshws-menu → Option 11 → Option 2
# Select backup file to restore
```

## Performance Optimization

### Enable BBR
```bash
sshws-menu → Option 12
# Enables BBR TCP congestion control
# Improves network performance
```

### Monitor Performance
```bash
# Run speed test
sshws-menu → Option 14

# Check bandwidth usage
vnstat

# Monitor connections
ss -s
```

## Security

### Check Security Status
```bash
# Fail2Ban status
sudo fail2ban-client status

# Firewall rules
sudo ufw status verbose

# Check for banned IPs
sudo fail2ban-client status sshd
```

### Update System
```bash
# Update packages
sudo apt update && sudo apt upgrade -y

# Update script
sshws-menu → Option 15
```

## Uninstallation

To completely remove SSHWS:

```bash
sshws-menu → Option 16
# Confirm with 'yes'
# This will remove all configurations and services
```

Or manually:
```bash
# Stop services
sudo systemctl stop nginx sshws v2ray-vmess v2ray-vless xhttp

# Remove files
sudo rm -rf /etc/sshws /etc/v2ray /etc/xhttp /var/lib/sshws

# Remove systemd services
sudo rm -f /etc/systemd/system/sshws.service
sudo rm -f /etc/systemd/system/v2ray-*.service
sudo rm -f /etc/systemd/system/xhttp.service
sudo systemctl daemon-reload
```

## Getting Help

- **Documentation**: See [README.md](README.md)
- **Quick Start**: See [QUICKSTART.md](QUICKSTART.md)
- **Examples**: See [examples/](examples/)
- **Issues**: [GitHub Issues](https://github.com/LamonLind/SSHWS/issues)
- **Discussions**: [GitHub Discussions](https://github.com/LamonLind/SSHWS/discussions)

## Additional Resources

- [NGINX Configuration Examples](examples/nginx-config.md)
- [V2Ray Configuration Examples](examples/v2ray-config.md)
- [Contributing Guidelines](CONTRIBUTING.md)
- [Changelog](CHANGELOG.md)

---

**For more detailed information, please refer to the [complete README](README.md).**
