# V2Ray Configuration Examples

## VMESS Configuration

### Server Configuration

**Location:** `/etc/v2ray/vmess-config.json`

```json
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
        "clients": [
          {
            "id": "your-uuid-here",
            "alterId": 0,
            "email": "user1@example.com"
          },
          {
            "id": "another-uuid-here",
            "alterId": 0,
            "email": "user2@example.com"
          }
        ]
      },
      "streamSettings": {
        "network": "ws",
        "wsSettings": {
          "path": "/vmess",
          "headers": {
            "Host": "your-domain.com"
          }
        }
      }
    }
  ],
  "outbounds": [
    {
      "protocol": "freedom",
      "settings": {}
    },
    {
      "protocol": "blackhole",
      "settings": {},
      "tag": "blocked"
    }
  ],
  "routing": {
    "rules": [
      {
        "type": "field",
        "ip": ["geoip:private"],
        "outboundTag": "blocked"
      }
    ]
  }
}
```

### Client Configuration

**V2RayN / V2RayNG:**

```json
{
  "v": "2",
  "ps": "MyServer-VMESS",
  "add": "your-domain.com",
  "port": "443",
  "id": "your-uuid-here",
  "aid": "0",
  "net": "ws",
  "type": "none",
  "host": "your-domain.com",
  "path": "/vmess",
  "tls": "tls",
  "sni": "your-domain.com"
}
```

**Connection Link:**
```
vmess://base64-encoded-json-config
```

## VLESS Configuration

### Server Configuration

**Location:** `/etc/v2ray/vless-config.json`

```json
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
        "clients": [
          {
            "id": "your-uuid-here",
            "email": "user1@example.com"
          },
          {
            "id": "another-uuid-here",
            "email": "user2@example.com"
          }
        ],
        "decryption": "none"
      },
      "streamSettings": {
        "network": "ws",
        "security": "none",
        "wsSettings": {
          "path": "/vless",
          "headers": {
            "Host": "your-domain.com"
          }
        }
      }
    }
  ],
  "outbounds": [
    {
      "protocol": "freedom",
      "settings": {}
    },
    {
      "protocol": "blackhole",
      "settings": {},
      "tag": "blocked"
    }
  ]
}
```

### Client Configuration

**Connection Link:**
```
vless://uuid@your-domain.com:443?type=ws&security=tls&path=/vless&host=your-domain.com#MyServer-VLESS
```

**Parameters:**
- `uuid` - Your user UUID
- `your-domain.com` - Your server domain
- `443` - HTTPS port
- `type=ws` - WebSocket transport
- `security=tls` - TLS encryption
- `path=/vless` - WebSocket path
- `host=your-domain.com` - Host header

## XHTTP/SplitHTTP Configuration

### Server Configuration

**Location:** `/etc/xhttp/config.json`

```json
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
        "clients": [
          {
            "id": "your-uuid-here",
            "email": "user1@example.com"
          }
        ],
        "decryption": "none"
      },
      "streamSettings": {
        "network": "splithttp",
        "security": "none",
        "splithttpSettings": {
          "path": "/xhttp",
          "host": "your-domain.com"
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
```

### Client Configuration

**Connection Link:**
```
vless://uuid@your-domain.com:443?type=splithttp&security=tls&path=/xhttp&host=your-domain.com#MyServer-XHTTP
```

## Advanced Configuration

### With CDN (Cloudflare)

For optimal CDN performance, modify streamSettings:

```json
"streamSettings": {
  "network": "ws",
  "security": "none",
  "wsSettings": {
    "path": "/vmess?ed=2048",
    "headers": {
      "Host": "your-domain.com"
    }
  }
}
```

### With Custom Headers

```json
"streamSettings": {
  "network": "ws",
  "wsSettings": {
    "path": "/vmess",
    "headers": {
      "Host": "your-domain.com",
      "User-Agent": "Mozilla/5.0",
      "X-Forwarded-For": "1.1.1.1"
    }
  }
}
```

### With Multiple Ports

Listen on multiple ports for fallback:

```json
"inbounds": [
  {
    "port": 10001,
    "listen": "127.0.0.1",
    "protocol": "vmess",
    "settings": { /* ... */ }
  },
  {
    "port": 10011,
    "listen": "127.0.0.1",
    "protocol": "vmess",
    "settings": { /* ... */ }
  }
]
```

## UUID Generation

Generate new UUID for users:

```bash
# Using uuidgen
uuidgen

# Or using V2Ray
v2ray uuid

# Or using Python
python3 -c "import uuid; print(uuid.uuid4())"
```

## Testing Configuration

Validate V2Ray configuration:

```bash
# Test VMESS config
v2ray test -c /etc/v2ray/vmess-config.json

# Test VLESS config
v2ray test -c /etc/v2ray/vless-config.json

# Test XHTTP config
v2ray test -c /etc/xhttp/config.json
```

## Service Management

```bash
# Start services
systemctl start v2ray-vmess
systemctl start v2ray-vless
systemctl start xhttp

# Check status
systemctl status v2ray-vmess
systemctl status v2ray-vless
systemctl status xhttp

# View logs
journalctl -u v2ray-vmess -f
journalctl -u v2ray-vless -f
journalctl -u xhttp -f

# Restart after config changes
systemctl restart v2ray-vmess
systemctl restart v2ray-vless
systemctl restart xhttp
```

## Client Applications

### Windows
- **V2RayN** - Most popular, feature-rich
- **Qv2ray** - Qt-based, modern UI

### Android
- **V2RayNG** - Official Android client
- **Matsuri** - Fork with additional features

### iOS
- **Shadowrocket** - Paid, best performance
- **Quantumult X** - Advanced features

### macOS
- **V2RayU** - Native macOS app
- **V2RayX** - Simple and lightweight

### Linux
- **Qv2ray** - Qt-based GUI
- **v2ray core** - Command line

## Troubleshooting

### Connection Issues

```bash
# Check if service is running
systemctl status v2ray-vmess

# Check if port is listening
netstat -tuln | grep 10001

# Check logs for errors
tail -f /var/log/v2ray/error.log
```

### Performance Issues

```bash
# Check CPU usage
top -p $(pgrep v2ray)

# Check memory usage
ps aux | grep v2ray

# Monitor connections
ss -tunap | grep v2ray
```

### Cloudflare Issues

If not working with Cloudflare:
1. Verify SSL/TLS mode is "Full (strict)"
2. Check WebSocket support is enabled
3. Try different CDN-friendly paths
4. Disable Cloudflare temporarily to test

## Security Best Practices

1. **Use strong UUIDs** - Generate unique UUIDs for each user
2. **Rotate UUIDs** - Change UUIDs periodically
3. **Monitor logs** - Check for unusual activity
4. **Limit users** - Don't create too many accounts
5. **Use firewall** - Allow only necessary ports
6. **Update regularly** - Keep V2Ray updated

## Performance Tuning

### System Limits

```bash
# Increase file descriptors
echo "* soft nofile 51200" >> /etc/security/limits.conf
echo "* hard nofile 51200" >> /etc/security/limits.conf
```

### V2Ray Optimization

```json
"policy": {
  "levels": {
    "0": {
      "handshake": 4,
      "connIdle": 300,
      "uplinkOnly": 2,
      "downlinkOnly": 5,
      "bufferSize": 10240
    }
  }
}
```

---

**For more information, see the [main documentation](../README.md).**
