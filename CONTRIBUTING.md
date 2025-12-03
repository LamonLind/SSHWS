# Contributing to SSHWS

Thank you for your interest in contributing to SSHWS! This document provides guidelines and instructions for contributing.

## 🤝 How to Contribute

### Reporting Bugs

If you find a bug, please open an issue with:
- Clear description of the problem
- Steps to reproduce
- Expected vs actual behavior
- System information (OS version, architecture)
- Relevant logs

### Suggesting Features

Feature requests are welcome! Please:
- Check if the feature already exists or is planned
- Describe the use case
- Explain why this would be useful
- Provide examples if possible

### Code Contributions

1. **Fork the Repository**
   ```bash
   git clone https://github.com/YourUsername/SSHWS.git
   cd SSHWS
   ```

2. **Create a Branch**
   ```bash
   git checkout -b feature/your-feature-name
   ```

3. **Make Your Changes**
   - Follow existing code style
   - Add comments for complex logic
   - Test your changes thoroughly

4. **Test Your Changes**
   ```bash
   # Syntax check
   bash -n install.sh
   
   # Test installation (use a VM or test server)
   ./install.sh
   ```

5. **Commit Your Changes**
   ```bash
   git add .
   git commit -m "Add feature: description of your changes"
   ```

6. **Push to Your Fork**
   ```bash
   git push origin feature/your-feature-name
   ```

7. **Create Pull Request**
   - Go to the original repository
   - Click "New Pull Request"
   - Select your branch
   - Describe your changes

## 📝 Coding Guidelines

### Bash Script Style

- Use 4 spaces for indentation
- Add comments for functions and complex logic
- Use meaningful variable names
- Validate user input
- Handle errors gracefully

Example:
```bash
# Good
validate_domain() {
    local domain=$1
    if ! [[ "$domain" =~ ^[a-zA-Z0-9.-]+$ ]]; then
        print_error "Invalid domain format"
        return 1
    fi
    return 0
}

# Bad
val_dom() {
    if ! [[ "$1" =~ ^[a-zA-Z0-9.-]+$ ]]; then
        echo "Error"
        return 1
    fi
}
```

### Error Handling

Always check for errors:
```bash
# Good
if ! systemctl start nginx; then
    print_error "Failed to start NGINX"
    return 1
fi

# Bad
systemctl start nginx
```

### User Messages

- Use colored output for clarity
- Provide helpful error messages
- Show progress during long operations

```bash
print_msg "Installing dependencies..."
print_success "Installation completed"
print_error "Failed to install package"
print_warning "Port 80 is already in use"
```

## 🧪 Testing

### Before Submitting

Test your changes on:
- Ubuntu 20.04 LTS
- Ubuntu 22.04 LTS
- Debian 10
- Debian 11

### Test Checklist

- [ ] Installation completes without errors
- [ ] All services start correctly
- [ ] Domain configuration works
- [ ] SSL certificate is obtained
- [ ] User creation works (SSH-WS, V2Ray, XHTTP)
- [ ] Menu system functions properly
- [ ] Firewall rules are applied
- [ ] Services survive reboot

## 📚 Documentation

When adding features:
- Update README.md
- Add examples if applicable
- Update QUICKSTART.md if relevant
- Add comments in code

## 🔒 Security

### Security Reports

**DO NOT** open public issues for security vulnerabilities.

Instead:
- Email security@example.com (replace with actual email)
- Provide detailed description
- Include steps to reproduce if possible
- Allow time for fix before public disclosure

### Security Guidelines

- Never commit credentials
- Validate all user input
- Use secure defaults
- Follow principle of least privilege
- Keep dependencies updated

## 🏗️ Project Structure

```
SSHWS/
├── install.sh           # Main installation script
├── README.md           # Main documentation
├── QUICKSTART.md       # Quick start guide
├── CONTRIBUTING.md     # This file
├── LICENSE             # MIT License
└── examples/           # Example configurations (future)
```

## 💡 Development Tips

### Testing Without Installation

You can test individual functions:
```bash
# Source the script
source install.sh

# Test specific function
detect_os
check_port_conflict 80
```

### Debugging

Enable debug mode:
```bash
bash -x install.sh
```

View detailed logs:
```bash
tail -f /var/log/sshws/install.log
```

## 📋 Pull Request Checklist

Before submitting a pull request:

- [ ] Code follows project style guidelines
- [ ] Changes are tested on supported OS versions
- [ ] Documentation is updated
- [ ] Commit messages are clear and descriptive
- [ ] No unnecessary files are included
- [ ] Security implications are considered
- [ ] Backward compatibility is maintained

## 🎯 Areas for Contribution

We especially welcome contributions in these areas:

### High Priority
- [ ] Support for more Linux distributions (CentOS, Fedora, etc.)
- [ ] IPv6 support
- [ ] Multi-language support
- [ ] Web-based management panel
- [ ] Docker containerization

### Medium Priority
- [ ] Integration with monitoring tools (Prometheus, Grafana)
- [ ] Automatic backup to cloud storage
- [ ] Email notifications for expiring users
- [ ] API for user management
- [ ] Mobile app for management

### Nice to Have
- [ ] Traffic statistics and graphs
- [ ] User bandwidth limiting
- [ ] Multiple domain support
- [ ] Load balancing setup
- [ ] High availability configuration

## 📞 Questions?

If you have questions about contributing:
- Open a discussion on GitHub
- Check existing issues and pull requests
- Read the full documentation

## 🙏 Thank You!

Every contribution helps make SSHWS better for everyone. We appreciate your time and effort!

---

**Happy coding! 🚀**
