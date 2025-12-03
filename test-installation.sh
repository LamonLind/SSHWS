#!/bin/bash

#############################################
# SSHWS Installation Test Script
# Validates that all components are properly installed
#############################################

# Color definitions
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Test counters
TESTS_PASSED=0
TESTS_FAILED=0

print_test() {
    echo -e "${CYAN}[TEST]${NC} $1"
}

print_pass() {
    echo -e "${GREEN}[PASS]${NC} $1"
    ((TESTS_PASSED++))
}

print_fail() {
    echo -e "${RED}[FAIL]${NC} $1"
    ((TESTS_FAILED++))
}

print_info() {
    echo -e "${YELLOW}[INFO]${NC} $1"
}

print_header() {
    clear
    echo -e "${CYAN}"
    echo "╔═══════════════════════════════════════════════════════╗"
    echo "║          SSHWS Installation Test Suite               ║"
    echo "╚═══════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

# Test directory structure
test_directories() {
    print_test "Checking directory structure..."
    
    local dirs=(
        "/etc/sshws"
        "/etc/v2ray"
        "/etc/xhttp"
        "/var/lib/sshws"
        "/var/log/sshws"
    )
    
    for dir in "${dirs[@]}"; do
        if [[ -d "$dir" ]]; then
            print_pass "Directory exists: $dir"
        else
            print_fail "Directory missing: $dir"
        fi
    done
}

# Test configuration files
test_config_files() {
    print_test "Checking configuration files..."
    
    local files=(
        "/etc/sshws/config.json"
        "/etc/v2ray/vmess-config.json"
        "/etc/v2ray/vless-config.json"
        "/etc/xhttp/config.json"
    )
    
    for file in "${files[@]}"; do
        if [[ -f "$file" ]]; then
            print_pass "Configuration exists: $file"
        else
            print_fail "Configuration missing: $file"
        fi
    done
}

# Test systemd services
test_services() {
    print_test "Checking systemd services..."
    
    local services=(
        "nginx"
        "sshws"
        "v2ray-vmess"
        "v2ray-vless"
        "xhttp"
    )
    
    for service in "${services[@]}"; do
        if systemctl is-enabled "$service" &>/dev/null; then
            if systemctl is-active "$service" &>/dev/null; then
                print_pass "Service running and enabled: $service"
            else
                print_fail "Service enabled but not running: $service"
            fi
        else
            print_fail "Service not enabled: $service"
        fi
    done
}

# Test ports
test_ports() {
    print_test "Checking listening ports..."
    
    local ports=(
        "80"
        "443"
        "8080"
        "8443"
    )
    
    for port in "${ports[@]}"; do
        if netstat -tuln | grep -q ":$port "; then
            print_pass "Port listening: $port"
        else
            print_fail "Port not listening: $port"
        fi
    done
}

# Test NGINX configuration
test_nginx() {
    print_test "Testing NGINX configuration..."
    
    if nginx -t &>/dev/null; then
        print_pass "NGINX configuration valid"
    else
        print_fail "NGINX configuration has errors"
    fi
}

# Test V2Ray installation
test_v2ray() {
    print_test "Testing V2Ray installation..."
    
    if command -v v2ray &>/dev/null; then
        print_pass "V2Ray binary installed"
        local version=$(v2ray version 2>&1 | head -1)
        print_info "V2Ray version: $version"
    else
        print_fail "V2Ray binary not found"
    fi
}

# Test required binaries
test_binaries() {
    print_test "Checking required binaries..."
    
    local binaries=(
        "curl"
        "wget"
        "jq"
        "certbot"
        "qrencode"
        "uuidgen"
    )
    
    for binary in "${binaries[@]}"; do
        if command -v "$binary" &>/dev/null; then
            print_pass "Binary installed: $binary"
        else
            print_fail "Binary missing: $binary"
        fi
    done
}

# Test firewall
test_firewall() {
    print_test "Checking firewall configuration..."
    
    if command -v ufw &>/dev/null; then
        if ufw status | grep -q "Status: active"; then
            print_pass "UFW firewall active"
            
            local ports=("80" "443" "8080" "8443")
            for port in "${ports[@]}"; do
                if ufw status | grep -q "$port"; then
                    print_pass "Firewall allows port: $port"
                else
                    print_fail "Firewall does not allow port: $port"
                fi
            done
        else
            print_fail "UFW firewall not active"
        fi
    else
        print_fail "UFW not installed"
    fi
}

# Test Fail2Ban
test_fail2ban() {
    print_test "Checking Fail2Ban..."
    
    if systemctl is-active fail2ban &>/dev/null; then
        print_pass "Fail2Ban is running"
    else
        print_fail "Fail2Ban is not running"
    fi
}

# Test management scripts
test_scripts() {
    print_test "Checking management scripts..."
    
    if [[ -x /usr/local/bin/sshws-menu ]]; then
        print_pass "Management menu installed"
    else
        print_fail "Management menu not installed or not executable"
    fi
    
    if [[ -f /usr/local/lib/sshws/functions.sh ]]; then
        print_pass "Function library installed"
    else
        print_fail "Function library not installed"
    fi
}

# Test SSL/TLS
test_ssl() {
    print_test "Checking SSL/TLS configuration..."
    
    if command -v certbot &>/dev/null; then
        print_pass "Certbot installed"
        
        # Check if any certificates exist
        if [[ -d /etc/letsencrypt/live ]]; then
            local cert_count=$(ls -1 /etc/letsencrypt/live | wc -l)
            if [[ $cert_count -gt 0 ]]; then
                print_pass "SSL certificates found: $cert_count domain(s)"
            else
                print_info "No SSL certificates installed yet (run domain configuration)"
            fi
        fi
    else
        print_fail "Certbot not installed"
    fi
}

# Test database
test_database() {
    print_test "Checking user database..."
    
    if [[ -f /var/lib/sshws/users.db ]]; then
        print_pass "User database file exists"
    else
        print_info "User database will be created on first user creation"
    fi
}

# Display summary
show_summary() {
    echo ""
    echo -e "${CYAN}╔═══════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║                   Test Summary                        ║${NC}"
    echo -e "${CYAN}╚═══════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "  ${GREEN}Passed:${NC} $TESTS_PASSED"
    echo -e "  ${RED}Failed:${NC} $TESTS_FAILED"
    echo ""
    
    if [[ $TESTS_FAILED -eq 0 ]]; then
        echo -e "${GREEN}✓ All tests passed! Installation appears to be successful.${NC}"
        echo ""
        echo "Next steps:"
        echo "1. Configure your domain: sshws-menu → Option 4"
        echo "2. Create users: sshws-menu → Options 1, 2, or 3"
        echo "3. Start using your VPN!"
    else
        echo -e "${RED}✗ Some tests failed. Please review the errors above.${NC}"
        echo ""
        echo "Troubleshooting:"
        echo "1. Check service logs: journalctl -u <service-name>"
        echo "2. Verify configuration files"
        echo "3. Check system logs: tail -f /var/log/syslog"
        echo "4. Re-run installation if necessary"
    fi
    echo ""
}

# Main execution
main() {
    print_header
    
    # Check if running as root
    if [[ $EUID -ne 0 ]]; then
        print_fail "This test script must be run as root"
        exit 1
    fi
    
    # Run all tests
    test_directories
    echo ""
    test_config_files
    echo ""
    test_services
    echo ""
    test_ports
    echo ""
    test_nginx
    echo ""
    test_v2ray
    echo ""
    test_binaries
    echo ""
    test_firewall
    echo ""
    test_fail2ban
    echo ""
    test_scripts
    echo ""
    test_ssl
    echo ""
    test_database
    
    # Show summary
    show_summary
    
    # Exit with appropriate code
    [[ $TESTS_FAILED -eq 0 ]] && exit 0 || exit 1
}

# Run main
main
