# Changelog

All notable changes to the SSHWS project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2024-12-03

### Added
- Initial release of SSHWS one-click installation script
- SSH WebSocket (SSH-WS) service support
- V2Ray VMESS protocol support with WebSocket
- V2Ray VLESS protocol support with WebSocket
- XHTTP/SplitHTTP tunnel support
- NGINX reverse proxy with optimized WebSocket configuration
- Automatic SSL certificate installation via Let's Encrypt
- Automatic SSL renewal via cron
- Full Cloudflare CDN compatibility
- Interactive management menu system with 16 options
- User management system (create, list, delete users)
- Domain configuration and management
- Port configuration for all services
- Service status monitoring
- Backup and restore functionality
- BBR TCP optimization support
- Fail2Ban integration for security
- UFW firewall configuration
- SpeedTest integration
- QR code generation for V2Ray users
- Comprehensive documentation (README.md)
- Quick start guide (QUICKSTART.md)
- Contributing guidelines (CONTRIBUTING.md)
- Example configurations (examples/)
- MIT License

### Services
- **SSH-WS**: WebSocket tunnel on port 10000 (internal)
- **V2Ray VMESS**: WebSocket on port 10001 (internal)
- **V2Ray VLESS**: WebSocket on port 10002 (internal)
- **XHTTP**: SplitHTTP on port 10003 (internal)
- **NGINX**: Reverse proxy on ports 80, 443, 8080, 8443

### Security Features
- Automatic SSL/TLS with Let's Encrypt
- TLS 1.2 and 1.3 support
- Fail2Ban integration
- UFW firewall rules
- Port conflict detection
- Domain validation
- Secure configuration file permissions
- Security headers in NGINX

### Management Features
1. Create SSH-WS users
2. Create V2Ray users (VLESS/VMESS)
3. Create XHTTP/SplitHTTP users
4. Configure/Add domain
5. Renew SSL certificates
6. Change service ports
7. Enable/Disable Cloudflare CDN mode
8. List all users
9. Delete users
10. Show service status
11. Backup/Restore configuration
12. Install BBR TCP optimization
13. Install Fail2Ban + Firewall rules
14. Run SpeedTest
15. Update script
16. Uninstall everything

### Technical Features
- Auto-detect OS version (Ubuntu/Debian)
- Dependency installation and management
- Systemd service creation for all components
- Configuration file management
- Log rotation and management
- Error handling and validation
- Modular and maintainable code structure

### Documentation
- Comprehensive README with installation instructions
- Quick start guide for fast deployment
- Contributing guidelines
- Example NGINX configurations
- Example V2Ray configurations
- Troubleshooting guide
- Security best practices
- Client application recommendations

### Supported Platforms
- Ubuntu 18.04 LTS and later
- Debian 9 and later
- Architecture: x64 (amd64)

## [Unreleased]

### Planned Features
- Support for additional Linux distributions (CentOS, Fedora)
- Web-based management panel
- Docker containerization
- IPv6 support
- Multi-language support
- Email notifications for expiring users
- API for user management
- Traffic statistics and monitoring
- User bandwidth limiting
- Multiple domain support
- Load balancing configuration
- High availability setup
- Integration with monitoring tools (Prometheus, Grafana)
- Automatic backup to cloud storage (S3, Dropbox, etc.)
- Mobile app for management

## Version History

### Version Numbering

- **Major version** (X.0.0): Incompatible changes, major rewrites
- **Minor version** (0.X.0): New features, backwards compatible
- **Patch version** (0.0.X): Bug fixes, minor improvements

### Release Schedule

- **Stable releases**: Tagged versions (e.g., v1.0.0)
- **Development**: main branch
- **Bug fixes**: Patch releases as needed

## How to Upgrade

### From Source

```bash
# Backup current installation
sshws-menu → Option 11 → Backup

# Download latest version
wget -O /tmp/install.sh https://raw.githubusercontent.com/LamonLind/SSHWS/main/install.sh

# Review changes
diff /tmp/install.sh /path/to/current/install.sh

# If satisfied, replace and run
chmod +x /tmp/install.sh
sudo /tmp/install.sh
```

### Using Management Menu

```bash
# From the menu
sshws-menu → Option 15 (Update script)
```

## Breaking Changes

None yet (v1.0.0 is the initial release)

## Deprecations

None yet

## Security Updates

Security updates will be released as patch versions and documented here.

To stay informed about security updates:
- Watch this repository on GitHub
- Subscribe to release notifications
- Check this changelog regularly

## Support

For questions, issues, or feature requests:
- Open an issue on GitHub
- Check the documentation
- Join discussions

---

**Note:** This changelog follows [Keep a Changelog](https://keepachangelog.com/) format.
All dates are in YYYY-MM-DD format.
