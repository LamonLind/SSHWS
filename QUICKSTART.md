# Quick Start Guide

## 🚀 Get Started in 5 Minutes

### Prerequisites
- Ubuntu 18.04+ or Debian 9+
- Root access
- Domain name pointing to your server
- Ports 80 and 443 open

### Step 1: Install

Run this single command as root:

```bash
wget -O install.sh https://raw.githubusercontent.com/LamonLind/SSHWS/main/install.sh && chmod +x install.sh && ./install.sh
```

Wait 5-10 minutes for installation to complete.

### Step 2: Configure Domain

After installation completes, run:

```bash
sshws-menu
```

Select option **4** and enter your domain name (e.g., `vpn.example.com`)

The script will:
- Configure NGINX
- Obtain SSL certificate from Let's Encrypt
- Set up auto-renewal

### Step 3: Create Your First User

From the menu, select option **1** (SSH-WS) or **2** (V2Ray):

**For SSH-WS:**
```
Username: testuser
Password: yourpassword
Expiry: 30 days
```

**For V2Ray:**
```
Username: testuser
Protocol: VMESS or VLESS
Expiry: 30 days
```

The script will generate:
- Connection details
- Configuration file
- QR code (V2Ray only)

### Step 4: Connect

**SSH-WS:**
```bash
ssh testuser@vpn.example.com
```

**V2Ray:**
- Scan QR code with your V2Ray client app
- Or manually enter the connection details

### Step 5: Enjoy!

Your tunnel is now ready. All traffic is encrypted and can work through Cloudflare CDN.

## 📱 Recommended Client Apps

### SSH-WS
- **Android**: HTTP Injector, HTTP Custom, KPN Tunnel Rev
- **PC**: OpenSSH client with proxy settings
- **iOS**: Shadowrocket (with SSH support)

### V2Ray
- **Windows**: V2RayN
- **Android**: V2RayNG
- **iOS**: Shadowrocket, Quantumult X
- **macOS**: V2RayU, V2RayX
- **Linux**: V2Ray core + GUI

## 🔧 Common Tasks

### Add More Users
```bash
sshws-menu → Option 1, 2, or 3
```

### Check Service Status
```bash
sshws-menu → Option 10
```

### Renew SSL Certificate
```bash
sshws-menu → Option 5
```

### Create Backup
```bash
sshws-menu → Option 11 → Option 1
```

### View All Users
```bash
sshws-menu → Option 8
```

## ☁️ Enable Cloudflare (Optional)

1. Add your domain to Cloudflare
2. Point A record to server IP
3. Enable proxy (orange cloud icon)
4. Set SSL mode to "Full (strict)"
5. Done! Your tunnel now works through Cloudflare CDN

## 🐛 Troubleshooting

### Installation Failed
```bash
# Check system requirements
uname -a
free -h
df -h

# Try again with verbose output
bash -x install.sh
```

### Can't Connect
```bash
# Check services
systemctl status nginx sshws v2ray-vmess

# Check firewall
sudo ufw status

# Check logs
tail -f /var/log/nginx/error.log
```

### SSL Certificate Issues
```bash
# Manual certificate request
sudo certbot certonly --standalone -d your-domain.com

# Check certificate
sudo certbot certificates
```

## 📞 Need Help?

- 📖 [Full Documentation](README.md)
- 🐛 [Report Issues](https://github.com/LamonLind/SSHWS/issues)
- 💬 [Discussions](https://github.com/LamonLind/SSHWS/discussions)

## 🎯 Next Steps

- ✅ Enable BBR for better performance (Option 12)
- ✅ Set up Fail2Ban for security (Option 13)
- ✅ Create regular backups (Option 11)
- ✅ Monitor service status regularly (Option 10)

---

**Happy tunneling! 🚀**
