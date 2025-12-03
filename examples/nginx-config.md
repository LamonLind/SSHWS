# Example NGINX Configuration for SSHWS

## Basic Configuration

This is an example NGINX configuration file for SSHWS with WebSocket support.

**Location:** `/etc/nginx/conf.d/sshws.conf`

```nginx
# HTTP Server - Redirect to HTTPS
server {
    listen 80;
    listen [::]:80;
    server_name vpn.example.com;

    # ACME challenge for Let's Encrypt
    location ^~ /.well-known/acme-challenge/ {
        root /var/www/html;
        allow all;
    }

    # Redirect all other traffic to HTTPS
    location / {
        return 301 https://$host$request_uri;
    }
}

# HTTPS Server with WebSocket Support
server {
    listen 443 ssl http2;
    listen [::]:443 ssl http2;
    listen 8443 ssl http2;
    listen [::]:8443 ssl http2;
    server_name vpn.example.com;

    # SSL Configuration
    ssl_certificate /etc/letsencrypt/live/vpn.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/vpn.example.com/privkey.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;
    ssl_prefer_server_ciphers on;
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 10m;

    # Security Headers
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-XSS-Protection "1; mode=block" always;

    # Root Directory
    root /var/www/html;
    index index.html;

    # SSH-WS WebSocket Endpoint
    location /ssh-ws {
        proxy_pass http://127.0.0.1:10000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        
        # Long timeout for WebSocket
        proxy_connect_timeout 7d;
        proxy_send_timeout 7d;
        proxy_read_timeout 7d;
    }

    # V2Ray VMESS WebSocket Endpoint
    location /vmess {
        proxy_pass http://127.0.0.1:10001;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_connect_timeout 60s;
        proxy_send_timeout 60s;
        proxy_read_timeout 60s;
    }

    # V2Ray VLESS WebSocket Endpoint
    location /vless {
        proxy_pass http://127.0.0.1:10002;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_connect_timeout 60s;
        proxy_send_timeout 60s;
        proxy_read_timeout 60s;
    }

    # XHTTP/SplitHTTP Endpoint
    location /xhttp {
        proxy_pass http://127.0.0.1:10003;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    }

    # Default Location
    location / {
        try_files $uri $uri/ =404;
    }
}

# Additional WebSocket Port (8080)
server {
    listen 8080;
    listen [::]:8080;
    server_name vpn.example.com;

    location /ssh-ws {
        proxy_pass http://127.0.0.1:10000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_connect_timeout 7d;
        proxy_send_timeout 7d;
        proxy_read_timeout 7d;
    }

    location / {
        return 404;
    }
}
```

## Configuration Notes

### WebSocket Settings

The WebSocket configuration includes:
- `proxy_http_version 1.1` - Required for WebSocket
- `Upgrade` and `Connection` headers - Enable WebSocket upgrade
- Long timeouts (7d) for persistent connections

### SSL Settings

- **TLS 1.2 and 1.3** - Modern encryption standards
- **Strong ciphers** - HIGH:!aNULL:!MD5
- **Session caching** - Improves performance

### Security Headers

- **HSTS** - Force HTTPS
- **X-Frame-Options** - Prevent clickjacking
- **X-Content-Type-Options** - Prevent MIME sniffing
- **X-XSS-Protection** - Enable XSS filter

## Testing Configuration

Test NGINX configuration before applying:

```bash
sudo nginx -t
```

Reload NGINX if test passes:

```bash
sudo systemctl reload nginx
```

## Cloudflare Compatibility

This configuration is fully compatible with Cloudflare CDN:

1. Enable proxy (orange cloud) in Cloudflare
2. Set SSL/TLS mode to "Full (strict)"
3. All WebSocket connections will work through Cloudflare

## Troubleshooting

### WebSocket Connection Fails

Check if WebSocket upgrade is working:

```bash
# Check NGINX error logs
tail -f /var/log/nginx/error.log

# Test WebSocket endpoint
curl -i -N -H "Connection: Upgrade" -H "Upgrade: websocket" \
  https://vpn.example.com/ssh-ws
```

### 502 Bad Gateway

Usually means backend service is not running:

```bash
# Check backend services
systemctl status sshws
netstat -tuln | grep 10000
```

### SSL Certificate Issues

Verify SSL certificate:

```bash
sudo certbot certificates
openssl s_client -connect vpn.example.com:443 -servername vpn.example.com
```

## Performance Optimization

For high-traffic servers, add these settings to `nginx.conf`:

```nginx
http {
    # Worker connections
    events {
        worker_connections 4096;
        use epoll;
    }

    # Keepalive settings
    keepalive_timeout 65;
    keepalive_requests 100;

    # Buffer sizes
    client_body_buffer_size 128k;
    client_max_body_size 50M;
    client_header_buffer_size 1k;
    large_client_header_buffers 4 4k;

    # Enable compression
    gzip on;
    gzip_vary on;
    gzip_proxied any;
    gzip_comp_level 6;
    gzip_types text/plain text/css text/xml text/javascript 
               application/json application/javascript application/xml+rss;
}
```

## Multiple Domains

To support multiple domains, create separate config files:

```bash
# Domain 1
/etc/nginx/conf.d/domain1.conf

# Domain 2
/etc/nginx/conf.d/domain2.conf
```

Each with different:
- `server_name`
- SSL certificates
- WebSocket paths

---

**For more information, see the [main documentation](../README.md).**
