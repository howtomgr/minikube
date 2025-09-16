# Minikube Installation Guide

Minikube is a free and open-source Container Orchestration. Local Kubernetes cluster for development and testing

## Table of Contents
1. [Prerequisites](#prerequisites)
2. [Supported Operating Systems](#supported-operating-systems)
3. [Installation](#installation)
4. [Configuration](#configuration)
5. [Service Management](#service-management)
6. [Troubleshooting](#troubleshooting)
7. [Security Considerations](#security-considerations)
8. [Performance Tuning](#performance-tuning)
9. [Backup and Restore](#backup-and-restore)
10. [System Requirements](#system-requirements)
11. [Support](#support)
12. [Contributing](#contributing)
13. [License](#license)
14. [Acknowledgments](#acknowledgments)
15. [Version History](#version-history)
16. [Appendices](#appendices)

## 1. Prerequisites

- **Hardware Requirements**:
  - CPU: 2 cores minimum (4+ cores recommended)
  - RAM: 2GB minimum (4GB+ recommended for production)
  - Storage: 10GB minimum
  - Network: 8443 ports required
- **Operating System**: 
  - Linux: Any modern distribution (RHEL, Debian, Ubuntu, CentOS, Fedora, Arch, Alpine, openSUSE)
  - macOS: 10.14+ (Mojave or newer)
  - Windows: Windows Server 2016+ or Windows 10 Pro
  - FreeBSD: 11.0+
- **Network Requirements**:
  - Port 8443 (default minikube port)
  - Firewall rules configured
- **Dependencies**:
  - docker, kubectl, virtualization
- **System Access**: root or sudo privileges required


## 2. Supported Operating Systems

This guide supports installation on:
- RHEL 8/9 and derivatives (CentOS Stream, Rocky Linux, AlmaLinux)
- Debian 11/12
- Ubuntu 20.04/22.04/24.04 LTS
- Arch Linux (rolling release)
- Alpine Linux 3.18+
- openSUSE Leap 15.5+ / Tumbleweed
- SUSE Linux Enterprise Server (SLES) 15+
- macOS 12+ (Monterey and later) 
- FreeBSD 13+
- Windows 10/11/Server 2019+ (where applicable)

## 3. Installation

### RHEL/CentOS/Rocky Linux/AlmaLinux

```bash
# Install EPEL repository if needed
sudo dnf install -y epel-release

# Install minikube
sudo dnf install -y minikube docker, kubectl, virtualization

# Enable and start service
sudo systemctl enable --now minikube

# Configure firewall
sudo firewall-cmd --permanent --add-service=minikube || \
  sudo firewall-cmd --permanent --add-port={default_port}/tcp
sudo firewall-cmd --reload

# Verify installation
minikube --version || systemctl status minikube
```

### Debian/Ubuntu

```bash
# Update package index
sudo apt update

# Install minikube
sudo apt install -y minikube docker, kubectl, virtualization

# Enable and start service
sudo systemctl enable --now minikube

# Configure firewall
sudo ufw allow 8443

# Verify installation
minikube --version || systemctl status minikube
```

### Arch Linux

```bash
# Install minikube
sudo pacman -S minikube

# Enable and start service
sudo systemctl enable --now minikube

# Verify installation
minikube --version || systemctl status minikube
```

### Alpine Linux

```bash
# Install minikube
apk add --no-cache minikube

# Enable and start service
rc-update add minikube default
rc-service minikube start

# Verify installation
minikube --version || rc-service minikube status
```

### openSUSE/SLES

```bash
# Install minikube
sudo zypper install -y minikube docker, kubectl, virtualization

# Enable and start service
sudo systemctl enable --now minikube

# Configure firewall
sudo firewall-cmd --permanent --add-service=minikube || \
  sudo firewall-cmd --permanent --add-port={default_port}/tcp
sudo firewall-cmd --reload

# Verify installation
minikube --version || systemctl status minikube
```

### macOS

```bash
# Using Homebrew
brew install minikube

# Start service
brew services start minikube

# Verify installation
minikube --version
```

### FreeBSD

```bash
# Using pkg
pkg install minikube

# Enable in rc.conf
echo 'minikube_enable="YES"' >> /etc/rc.conf

# Start service
service minikube start

# Verify installation
minikube --version || service minikube status
```

### Windows

```powershell
# Using Chocolatey
choco install minikube

# Or using Scoop
scoop install minikube

# Verify installation
minikube --version
```

## Initial Configuration

### Basic Configuration

```bash
# Create configuration directory if needed
sudo mkdir -p $HOME/.minikube

# Set up basic configuration
sudo tee $HOME/.minikube/minikube.conf << 'EOF'
# Minikube Configuration
--cpus=4 --memory=8192 --disk-size=50g
EOF

# Set appropriate permissions
sudo chown -R minikube:minikube $HOME/.minikube || \
  sudo chown -R $(whoami):$(whoami) $HOME/.minikube

# Test configuration
sudo minikube --test || sudo minikube configtest
```

### Security Hardening

```bash
# Create dedicated user (if not created by package)
sudo useradd --system --shell /bin/false minikube || true

# Secure configuration files
sudo chmod 750 $HOME/.minikube
sudo chmod 640 $HOME/.minikube/*.conf

# Enable security features
# See security section for detailed hardening steps
```

## 5. Service Management

### systemd (RHEL, Debian, Ubuntu, Arch, openSUSE)

```bash
# Enable service
sudo systemctl enable minikube

# Start service
sudo systemctl start minikube

# Stop service
sudo systemctl stop minikube

# Restart service
sudo systemctl restart minikube

# Reload configuration
sudo systemctl reload minikube

# Check status
sudo systemctl status minikube

# View logs
sudo journalctl -u minikube -f
```

### OpenRC (Alpine Linux)

```bash
# Enable service
rc-update add minikube default

# Start service
rc-service minikube start

# Stop service
rc-service minikube stop

# Restart service
rc-service minikube restart

# Check status
rc-service minikube status

# View logs
tail -f $HOME/.minikube/logs/minikube.log
```

### rc.d (FreeBSD)

```bash
# Enable in /etc/rc.conf
echo 'minikube_enable="YES"' >> /etc/rc.conf

# Start service
service minikube start

# Stop service
service minikube stop

# Restart service
service minikube restart

# Check status
service minikube status
```

### launchd (macOS)

```bash
# Using Homebrew services
brew services start minikube
brew services stop minikube
brew services restart minikube

# Check status
brew services list | grep minikube

# View logs
tail -f $(brew --prefix)/var/log/minikube.log
```

### Windows Service Manager

```powershell
# Start service
net start minikube

# Stop service
net stop minikube

# Using PowerShell
Start-Service minikube
Stop-Service minikube
Restart-Service minikube

# Check status
Get-Service minikube

# Set to automatic startup
Set-Service minikube -StartupType Automatic
```

## Advanced Configuration

### Performance Optimization

```bash
# Configure performance settings
cat >> $HOME/.minikube/minikube.conf << 'EOF'
# Performance tuning
--cpus=4 --memory=8192 --disk-size=50g
EOF

# Apply system tuning
sudo sysctl -w net.core.somaxconn=65535
sudo sysctl -w net.ipv4.tcp_max_syn_backlog=65535
echo "vm.swappiness=10" | sudo tee -a /etc/sysctl.conf
sudo sysctl -p

# Restart service to apply changes
sudo systemctl restart minikube
```

### High Availability Setup

```bash
# Configure clustering/HA (if supported)
# This varies greatly by tool - see official documentation

# Example load balancing configuration
# Configure multiple instances on different ports
# Use HAProxy or nginx for load balancing
```

## Reverse Proxy Setup

### nginx Configuration

```nginx
upstream minikube_backend {
    server 127.0.0.1:8443;
    keepalive 32;
}

server {
    listen 80;
    server_name minikube.example.com;
    return 301 https://$server_name$request_uri;
}

server {
    listen 443 ssl http2;
    server_name minikube.example.com;

    ssl_certificate /etc/ssl/certs/minikube.crt;
    ssl_certificate_key /etc/ssl/private/minikube.key;

    # Security headers
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    add_header X-Content-Type-Options nosniff;
    add_header X-Frame-Options SAMEORIGIN;
    add_header X-XSS-Protection "1; mode=block";

    location / {
        proxy_pass http://minikube_backend;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        
        # WebSocket support (if needed)
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        
        # Timeouts
        proxy_connect_timeout 60s;
        proxy_send_timeout 60s;
        proxy_read_timeout 60s;
    }
}
```

### Apache Configuration

```apache
<VirtualHost *:80>
    ServerName minikube.example.com
    Redirect permanent / https://minikube.example.com/
</VirtualHost>

<VirtualHost *:443>
    ServerName minikube.example.com
    
    SSLEngine on
    SSLCertificateFile /etc/ssl/certs/minikube.crt
    SSLCertificateKeyFile /etc/ssl/private/minikube.key
    
    # Security headers
    Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains"
    Header always set X-Content-Type-Options nosniff
    Header always set X-Frame-Options SAMEORIGIN
    Header always set X-XSS-Protection "1; mode=block"
    
    ProxyRequests Off
    ProxyPreserveHost On
    
    <Location />
        ProxyPass http://127.0.0.1:8443/
        ProxyPassReverse http://127.0.0.1:8443/
    </Location>
    
    # WebSocket support (if needed)
    RewriteEngine on
    RewriteCond %{HTTP:Upgrade} websocket [NC]
    RewriteCond %{HTTP:Connection} upgrade [NC]
    RewriteRule ^/?(.*) "ws://127.0.0.1:8443/$1" [P,L]
</VirtualHost>
```

### HAProxy Configuration

```haproxy
global
    maxconn 4096
    log /dev/log local0
    chroot /var/lib/haproxy
    user haproxy
    group haproxy
    daemon

defaults
    log global
    mode http
    option httplog
    option dontlognull
    timeout connect 5000
    timeout client 50000
    timeout server 50000

frontend minikube_frontend
    bind *:80
    bind *:443 ssl crt /etc/ssl/certs/minikube.pem
    redirect scheme https if !{ ssl_fc }
    
    # Security headers
    http-response set-header Strict-Transport-Security "max-age=31536000; includeSubDomains"
    http-response set-header X-Content-Type-Options nosniff
    http-response set-header X-Frame-Options SAMEORIGIN
    http-response set-header X-XSS-Protection "1; mode=block"
    
    default_backend minikube_backend

backend minikube_backend
    balance roundrobin
    option httpchk GET /health
    server minikube1 127.0.0.1:8443 check
```

### Caddy Configuration

```caddy
minikube.example.com {
    reverse_proxy 127.0.0.1:8443 {
        header_up Host {upstream_hostport}
        header_up X-Real-IP {remote}
        header_up X-Forwarded-For {remote}
        header_up X-Forwarded-Proto {scheme}
    }
    
    header {
        Strict-Transport-Security "max-age=31536000; includeSubDomains"
        X-Content-Type-Options nosniff
        X-Frame-Options SAMEORIGIN
        X-XSS-Protection "1; mode=block"
    }
    
    encode gzip
}
```

## Security Configuration

### Basic Security Setup

```bash
# Create dedicated user
sudo useradd --system --shell /bin/false --home $HOME/.minikube minikube || true

# Set ownership
sudo chown -R minikube:minikube $HOME/.minikube
sudo chown -R minikube:minikube $HOME/.minikube/logs

# Set permissions
sudo chmod 750 $HOME/.minikube
sudo chmod 640 $HOME/.minikube/*
sudo chmod 750 $HOME/.minikube/logs

# Configure firewall (UFW)
sudo ufw allow from any to any port 8443 proto tcp comment "Minikube"

# Configure firewall (firewalld)
sudo firewall-cmd --permanent --new-service=minikube
sudo firewall-cmd --permanent --service=minikube --add-port={default_port}/tcp
sudo firewall-cmd --permanent --add-service=minikube
sudo firewall-cmd --reload

# SELinux configuration (if enabled)
sudo setsebool -P httpd_can_network_connect on
sudo semanage port -a -t http_port_t -p tcp 8443 || true
```

### SSL/TLS Configuration

```bash
# Generate self-signed certificate (for testing)
sudo openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
    -keyout /etc/ssl/private/minikube.key \
    -out /etc/ssl/certs/minikube.crt \
    -subj "/C=US/ST=State/L=City/O=Organization/CN=minikube.example.com"

# Set proper permissions
sudo chmod 600 /etc/ssl/private/minikube.key
sudo chmod 644 /etc/ssl/certs/minikube.crt

# For production, use Let's Encrypt
sudo certbot certonly --standalone -d minikube.example.com
```

### Fail2ban Configuration

```ini
# /etc/fail2ban/jail.d/minikube.conf
[minikube]
enabled = true
port = 8443
filter = minikube
logpath = $HOME/.minikube/logs/*.log
maxretry = 5
bantime = 3600
findtime = 600
```

```ini
# /etc/fail2ban/filter.d/minikube.conf
[Definition]
failregex = ^.*Failed login attempt.*from <HOST>.*$
            ^.*Authentication failed.*from <HOST>.*$
            ^.*Invalid credentials.*from <HOST>.*$
ignoreregex =
```

## Database Setup

### PostgreSQL Backend (if applicable)

```bash
# Create database and user
sudo -u postgres psql << EOF
CREATE DATABASE minikube_db;
CREATE USER minikube_user WITH ENCRYPTED PASSWORD 'secure_password_here';
GRANT ALL PRIVILEGES ON DATABASE minikube_db TO minikube_user;
\q
EOF

# Configure connection in Minikube
echo "DATABASE_URL=postgresql://minikube_user:secure_password_here@localhost/minikube_db" | \
  sudo tee -a $HOME/.minikube/minikube.env
```

### MySQL/MariaDB Backend (if applicable)

```bash
# Create database and user
sudo mysql << EOF
CREATE DATABASE minikube_db CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
CREATE USER 'minikube_user'@'localhost' IDENTIFIED BY 'secure_password_here';
GRANT ALL PRIVILEGES ON minikube_db.* TO 'minikube_user'@'localhost';
FLUSH PRIVILEGES;
EOF

# Configure connection
echo "DATABASE_URL=mysql://minikube_user:secure_password_here@localhost/minikube_db" | \
  sudo tee -a $HOME/.minikube/minikube.env
```

### SQLite Backend (if applicable)

```bash
# Create database directory
sudo mkdir -p /var/lib/minikube
sudo chown minikube:minikube /var/lib/minikube

# Initialize database
sudo -u minikube minikube init-db
```

## Performance Optimization

### System Tuning

```bash
# Kernel parameters for better performance
cat << 'EOF' | sudo tee -a /etc/sysctl.conf
# Network performance tuning
net.core.somaxconn = 65535
net.ipv4.tcp_max_syn_backlog = 65535
net.ipv4.ip_local_port_range = 1024 65535
net.core.netdev_max_backlog = 5000
net.ipv4.tcp_tw_reuse = 1

# Memory tuning
vm.swappiness = 10
vm.dirty_ratio = 15
vm.dirty_background_ratio = 5
EOF

# Apply settings
sudo sysctl -p

# Configure system limits
cat << 'EOF' | sudo tee -a /etc/security/limits.conf
minikube soft nofile 65535
minikube hard nofile 65535
minikube soft nproc 32768
minikube hard nproc 32768
EOF
```

### Application Tuning

```bash
# Configure application-specific performance settings
cat << 'EOF' | sudo tee -a $HOME/.minikube/performance.conf
# Performance configuration
--cpus=4 --memory=8192 --disk-size=50g

# Connection pooling
max_connections = 1000
connection_timeout = 30

# Cache settings
cache_size = 256M
cache_ttl = 3600

# Worker processes
workers = 4
threads_per_worker = 4
EOF

# Restart to apply settings
sudo systemctl restart minikube
```

## Monitoring

### Prometheus Integration

```yaml
# /etc/prometheus/prometheus.yml
scrape_configs:
  - job_name: 'minikube'
    static_configs:
      - targets: ['localhost:8443/metrics']
    metrics_path: '/metrics'
    scrape_interval: 30s
```

### Health Check Script

```bash
#!/bin/bash
# /usr/local/bin/minikube-health

# Check if service is running
if ! systemctl is-active --quiet minikube; then
    echo "CRITICAL: Minikube service is not running"
    exit 2
fi

# Check if port is listening
if ! nc -z localhost 8443 2>/dev/null; then
    echo "CRITICAL: Minikube is not listening on port 8443"
    exit 2
fi

# Check response time
response_time=$(curl -o /dev/null -s -w '%{time_total}' http://localhost:8443/health || echo "999")
if (( $(echo "$response_time > 5" | bc -l) )); then
    echo "WARNING: Slow response time: ${response_time}s"
    exit 1
fi

echo "OK: Minikube is healthy (response time: ${response_time}s)"
exit 0
```

### Log Monitoring

```bash
# Configure log rotation
cat << 'EOF' | sudo tee /etc/logrotate.d/minikube
$HOME/.minikube/logs/*.log {
    daily
    rotate 14
    compress
    delaycompress
    missingok
    notifempty
    create 0640 minikube minikube
    postrotate
        systemctl reload minikube > /dev/null 2>&1 || true
    endscript
}
EOF

# Test log rotation
sudo logrotate -d /etc/logrotate.d/minikube
```

## 9. Backup and Restore

### Backup Script

```bash
#!/bin/bash
# /usr/local/bin/minikube-backup

BACKUP_DIR="/backup/minikube"
DATE=$(date +%Y%m%d_%H%M%S)
BACKUP_FILE="$BACKUP_DIR/minikube_backup_$DATE.tar.gz"

# Create backup directory
mkdir -p "$BACKUP_DIR"

# Stop service (if needed for consistency)
echo "Stopping Minikube service..."
systemctl stop minikube

# Backup configuration
echo "Backing up configuration..."
tar -czf "$BACKUP_FILE" \
    $HOME/.minikube \
    /var/lib/minikube \
    $HOME/.minikube/logs

# Backup database (if applicable)
if command -v pg_dump &> /dev/null; then
    echo "Backing up database..."
    sudo -u postgres pg_dump minikube_db | gzip > "$BACKUP_DIR/minikube_db_$DATE.sql.gz"
fi

# Start service
echo "Starting Minikube service..."
systemctl start minikube

# Clean old backups (keep 30 days)
find "$BACKUP_DIR" -name "*.tar.gz" -mtime +30 -delete
find "$BACKUP_DIR" -name "*.sql.gz" -mtime +30 -delete

echo "Backup completed: $BACKUP_FILE"
```

### Restore Script

```bash
#!/bin/bash
# /usr/local/bin/minikube-restore

if [ $# -ne 1 ]; then
    echo "Usage: $0 <backup_file>"
    exit 1
fi

BACKUP_FILE="$1"

if [ ! -f "$BACKUP_FILE" ]; then
    echo "Error: Backup file not found: $BACKUP_FILE"
    exit 1
fi

# Stop service
echo "Stopping Minikube service..."
systemctl stop minikube

# Restore files
echo "Restoring from backup..."
tar -xzf "$BACKUP_FILE" -C /

# Restore database (if applicable)
DB_BACKUP=$(echo "$BACKUP_FILE" | sed 's/.tar.gz$/_db.sql.gz/')
if [ -f "$DB_BACKUP" ]; then
    echo "Restoring database..."
    zcat "$DB_BACKUP" | sudo -u postgres psql minikube_db
fi

# Fix permissions
chown -R minikube:minikube $HOME/.minikube
chown -R minikube:minikube /var/lib/minikube

# Start service
echo "Starting Minikube service..."
systemctl start minikube

echo "Restore completed successfully"
```

## 6. Troubleshooting

### Common Issues

1. **Service won't start**:
```bash
# Check service status and logs
sudo systemctl status minikube
sudo journalctl -u minikube -n 100 --no-pager

# Check for port conflicts
sudo ss -tlnp | grep 8443
sudo lsof -i :8443

# Verify configuration
sudo minikube --test || sudo minikube configtest

# Check permissions
ls -la $HOME/.minikube
ls -la $HOME/.minikube/logs
```

2. **Cannot access web interface**:
```bash
# Check if service is listening
sudo ss -tlnp | grep minikube
curl -I http://localhost:8443

# Check firewall rules
sudo firewall-cmd --list-all
sudo iptables -L -n | grep 8443

# Check SELinux (if enabled)
getenforce
sudo ausearch -m avc -ts recent | grep minikube
```

3. **High memory/CPU usage**:
```bash
# Monitor resource usage
top -p $(pgrep minikube)
htop -p $(pgrep minikube)

# Check for memory leaks
ps aux | grep minikube
cat /proc/$(pgrep minikube)/status | grep -i vm

# Analyze logs for errors
grep -i error $HOME/.minikube/logs/*.log | tail -50
```

4. **Database connection errors**:
```bash
# Test database connection
psql -U minikube_user -d minikube_db -c "SELECT 1;"
mysql -u minikube_user -p minikube_db -e "SELECT 1;"

# Check database service
sudo systemctl status postgresql
sudo systemctl status mariadb
```

### Debug Mode

```bash
# Enable debug logging
echo "debug = true" | sudo tee -a $HOME/.minikube/minikube.conf

# Restart with debug mode
sudo systemctl stop minikube
sudo -u minikube minikube --debug

# Watch debug logs
tail -f $HOME/.minikube/logs/debug.log
```

### Performance Analysis

```bash
# Profile CPU usage
sudo perf record -p $(pgrep minikube) sleep 30
sudo perf report

# Analyze network traffic
sudo tcpdump -i any -w /tmp/minikube.pcap port 8443
sudo tcpdump -r /tmp/minikube.pcap -nn

# Monitor disk I/O
sudo iotop -p $(pgrep minikube)
```

## Integration Examples

### Docker Deployment

```yaml
# docker-compose.yml
version: '3.8'

services:
  minikube:
    image: minikube:minikube
    container_name: minikube
    restart: unless-stopped
    ports:
      - "8443:8443"
    environment:
      - TZ=UTC
      - PUID=1000
      - PGID=1000
    volumes:
      - ./config:$HOME/.minikube
      - ./data:/var/lib/minikube
      - ./logs:$HOME/.minikube/logs
    networks:
      - minikube_network
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8443/health"]
      interval: 30s
      timeout: 10s
      retries: 3

networks:
  minikube_network:
    driver: bridge
```

### Kubernetes Deployment

```yaml
# minikube-deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: minikube
  labels:
    app: minikube
spec:
  replicas: 1
  selector:
    matchLabels:
      app: minikube
  template:
    metadata:
      labels:
        app: minikube
    spec:
      containers:
      - name: minikube
        image: minikube:minikube
        ports:
        - containerPort: 8443
        env:
        - name: TZ
          value: UTC
        volumeMounts:
        - name: config
          mountPath: $HOME/.minikube
        - name: data
          mountPath: /var/lib/minikube
        livenessProbe:
          httpGet:
            path: /health
            port: 8443
          initialDelaySeconds: 30
          periodSeconds: 30
        readinessProbe:
          httpGet:
            path: /ready
            port: 8443
          initialDelaySeconds: 5
          periodSeconds: 10
      volumes:
      - name: config
        configMap:
          name: minikube-config
      - name: data
        persistentVolumeClaim:
          claimName: minikube-data
---
apiVersion: v1
kind: Service
metadata:
  name: minikube
spec:
  selector:
    app: minikube
  ports:
  - protocol: TCP
    port: 8443
    targetPort: 8443
  type: LoadBalancer
---
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: minikube-data
spec:
  accessModes:
    - ReadWriteOnce
  resources:
    requests:
      storage: 10Gi
```

### Ansible Playbook

```yaml
---
# minikube-playbook.yml
- name: Install and configure Minikube
  hosts: all
  become: yes
  vars:
    minikube_version: latest
    minikube_port: 8443
    minikube_config_dir: $HOME/.minikube
  
  tasks:
    - name: Install dependencies
      package:
        name:
          - docker, kubectl, virtualization
        state: present
    
    - name: Install Minikube
      package:
        name: minikube
        state: present
    
    - name: Create configuration directory
      file:
        path: "{{ minikube_config_dir }}"
        state: directory
        owner: minikube
        group: minikube
        mode: '0750'
    
    - name: Deploy configuration
      template:
        src: minikube.conf.j2
        dest: "{{ minikube_config_dir }}/minikube.conf"
        owner: minikube
        group: minikube
        mode: '0640'
      notify: restart minikube
    
    - name: Start and enable service
      systemd:
        name: minikube
        state: started
        enabled: yes
        daemon_reload: yes
    
    - name: Configure firewall
      firewalld:
        port: "{{ minikube_port }}/tcp"
        permanent: yes
        immediate: yes
        state: enabled
  
  handlers:
    - name: restart minikube
      systemd:
        name: minikube
        state: restarted
```

### Terraform Configuration

```hcl
# minikube.tf
resource "aws_instance" "minikube_server" {
  ami           = var.ami_id
  instance_type = "t3.medium"
  
  vpc_security_group_ids = [aws_security_group.minikube.id]
  
  user_data = <<-EOF
    #!/bin/bash
    # Install Minikube
    apt-get update
    apt-get install -y minikube docker, kubectl, virtualization
    
    # Configure Minikube
    systemctl enable minikube
    systemctl start minikube
  EOF
  
  tags = {
    Name = "Minikube Server"
    Application = "Minikube"
  }
}

resource "aws_security_group" "minikube" {
  name        = "minikube-sg"
  description = "Security group for Minikube"
  
  ingress {
    from_port   = 8443
    to_port     = 8443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
  
  tags = {
    Name = "Minikube Security Group"
  }
}
```

## Maintenance

### Update Procedures

```bash
# RHEL/CentOS/Rocky/AlmaLinux
sudo dnf check-update minikube
sudo dnf update minikube

# Debian/Ubuntu
sudo apt update
sudo apt upgrade minikube

# Arch Linux
sudo pacman -Syu minikube

# Alpine Linux
apk update
apk upgrade minikube

# openSUSE
sudo zypper ref
sudo zypper update minikube

# FreeBSD
pkg update
pkg upgrade minikube

# Always backup before updates
/usr/local/bin/minikube-backup

# Restart after updates
sudo systemctl restart minikube
```

### Regular Maintenance Tasks

```bash
# Clean old logs
find $HOME/.minikube/logs -name "*.log" -mtime +30 -delete

# Vacuum database (if PostgreSQL)
sudo -u postgres vacuumdb --analyze minikube_db

# Check disk usage
df -h | grep -E "(/$|minikube)"
du -sh /var/lib/minikube

# Update security patches
sudo unattended-upgrade -d

# Review security logs
sudo aureport --summary
sudo journalctl -u minikube | grep -i "error\|fail\|deny"
```

### Health Monitoring Checklist

- [ ] Service is running and enabled
- [ ] Web interface is accessible
- [ ] Database connections are healthy
- [ ] Disk usage is below 80%
- [ ] No critical errors in logs
- [ ] Backups are running successfully
- [ ] SSL certificates are valid
- [ ] Security updates are applied

## Additional Resources

- Official Documentation: https://docs.minikube.org/
- GitHub Repository: https://github.com/minikube/minikube
- Community Forum: https://forum.minikube.org/
- Wiki: https://wiki.minikube.org/
- Docker Hub: https://hub.docker.com/r/minikube/minikube
- Security Advisories: https://security.minikube.org/
- Best Practices: https://docs.minikube.org/best-practices
- API Documentation: https://api.minikube.org/
- Comparison with k3s, kind, Docker Desktop, MicroK8s: https://docs.minikube.org/comparison

---

**Note:** This guide is part of the [HowToMgr](https://howtomgr.github.io) collection. Always refer to official documentation for the most up-to-date information.
