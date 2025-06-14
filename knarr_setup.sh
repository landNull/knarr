#!/bin/bash

# Debian 12 Post-Install Configuration Script
# Hostname: knarr.star
# CPU: 8-core AMD FX-8320E
# RAM: 32GB

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging function
log() {
    echo -e "${GREEN}[$(date +'%Y-%m-%d %H:%M:%S')] $1${NC}"
}

warn() {
    echo -e "${YELLOW}[$(date +'%Y-%m-%d %H:%M:%S')] WARNING: $1${NC}"
}

error() {
    echo -e "${RED}[$(date +'%Y-%m-%d %H:%M:%S')] ERROR: $1${NC}"
    exit 1
}

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   error "This script must be run as root"
fi

# Check if running on Debian 12
if ! grep -q "ID=debian" /etc/os-release || ! grep -q "VERSION_ID=\"12\"" /etc/os-release; then
    error "This script is designed for Debian 12 only"
fi

# Create backup directory for original configs
BACKUP_DIR="/root/config_backups_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$BACKUP_DIR"
log "Configuration backups will be stored in: $BACKUP_DIR"

log "Starting Debian 12 post-install configuration for knarr.star"

# Set hostname
log "Setting hostname to knarr.star"
hostnamectl set-hostname knarr.star
echo "127.0.0.1 knarr.star" >> /etc/hosts

# Update system
log "Updating system packages"
apt-get update && apt-get upgrade -y

# Install base utilities
log "Installing base utilities"
apt-get install -y wget curl git mdadm procps ca-certificates

# Configure network interface
log "Configuring network interface"
[[ -f /etc/network/interfaces ]] && cp /etc/network/interfaces "$BACKUP_DIR/"
cat > /etc/network/interfaces << 'EOF'
auto lo
iface lo inet loopback
auto eth0
iface eth0 inet static
  address 192.168.1.120
  netmask 255.255.255.0
  gateway 192.168.1.1
  dns-nameservers 1.1.1.1 1.0.0.1
EOF

# Configure DNS resolution
log "Configuring DNS resolution"
[[ -f /etc/resolv.conf ]] && cp /etc/resolv.conf "$BACKUP_DIR/"
cat > /etc/resolv.conf << 'EOF'
nameserver 127.0.0.1
nameserver 1.1.1.1
nameserver 1.0.0.1
EOF

# Make resolv.conf immutable to prevent overwrites
chattr +i /etc/resolv.conf

# Install and configure DNSmasq
log "Installing and configuring DNSmasq"
apt-get install -y dnsmasq dnsmasq-utils

cat > /etc/dnsmasq.conf << 'EOF'
domain-needed
bogus-priv
no-resolv
no-poll
no-hosts
listen-address=127.0.0.1,192.168.1.120
bind-interfaces
except-interface=lo
local=/knarr/
domain=knarr
server=1.1.1.1
server=1.0.0.1
cache-size=20000
dns-forward-max=500
min-cache-ttl=3600
neg-ttl=600
no-dhcp-interface=
conf-dir=/etc/dnsmasq.d/,*.conf
log-queries
log-facility=/var/log/dnsmasq.log
EOF

# Create wildcard DNS configurations
mkdir -p /etc/dnsmasq.d
cat > /etc/dnsmasq.d/wildcards.conf << 'EOF'
address=/dev/192.168.1.120
address=/test/192.168.1.120
address=/star/192.168.1.120
EOF

# Configure users and shells
log "Setting up users and shell configuration"

# Install shell dependencies
apt-get install -y zsh git curl micro

# Clone antidote for zsh plugin management
if [[ ! -d /usr/local/share/antidote ]]; then
    git clone --depth=1 https://github.com/mattmc3/antidote.git /usr/local/share/antidote
else
    log "Antidote already installed, skipping clone"
fi

# Create zsh plugins configuration
mkdir -p /etc/antidote
cat > /etc/antidote/zsh_plugins.txt << 'EOF'
jeffreytse/zsh-vi-mode
rupa/z
romkatv/zsh-bench kind:path
olets/zsh-abbr kind:defer
mattmc3/ez-compinit
zsh-users/zsh-completions kind:fpath path:src
getantidote/use-omz
ohmyzsh/ohmyzsh path:lib
ohmyzsh/ohmyzsh path:plugins/colored-man-pages
ohmyzsh/ohmyzsh path:plugins/magic-enter
belak/zsh-utils path:editor
belak/zsh-utils path:history
belak/zsh-utils path:prompt
belak/zsh-utils path:utility
sindresorhus/pure kind:fpath
romkatv/powerlevel10k kind:fpath
mattmc3/zfunctions
zsh-users/zsh-autosuggestions
zdharma-continuum/fast-syntax-highlighting kind:defer
zsh-users/zsh-history-substring-search
EOF

# Configure root shell
log "Configuring root shell"
chsh -s /bin/zsh root
cat > /root/.zshrc << 'EOF'
source /usr/local/share/antidote/antidote.zsh
antidote load /etc/antidote/zsh_plugins.txt
autoload -Uz promptinit && promptinit && prompt pure
EOF

# Configure root's micro editor
mkdir -p /root/.config/micro
cat > /root/.config/micro/settings.json << 'EOF'
{
  "mkparents": true
}
EOF

# Create heimdall user
log "Creating heimdall user"
if ! id heimdall &>/dev/null; then
    useradd -m -s /bin/zsh heimdall
    log "User heimdall created successfully"
else
    log "User heimdall already exists, skipping creation"
fi

# Configure heimdall shell
cat > /home/heimdall/.zshrc << 'EOF'
source /usr/local/share/antidote/antidote.zsh
antidote load /etc/antidote/zsh_plugins.txt
autoload -Uz promptinit && promptinit && prompt pure
EOF

# Configure heimdall's micro editor
mkdir -p /home/heimdall/.config/micro
cat > /home/heimdall/.config/micro/settings.json << 'EOF'
{
  "mkparents": true,
  "autosu": true
}
EOF

chown -R heimdall:heimdall /home/heimdall

# Configure sudo for heimdall
apt-get install -y sudo
cat > /etc/sudoers.d/heimdall << 'EOF'
heimdall ALL=(ALL) NOPASSWD:ALL
EOF

# Performance tweaks
log "Applying performance tweaks"

# Sysctl configuration
cat > /etc/sysctl.d/99-performance.conf << 'EOF'
# Network optimizations
net.core.somaxconn=65535
net.core.netdev_max_backlog=5000
net.ipv4.tcp_max_syn_backlog=8192
net.ipv4.tcp_rmem=4096 87380 16777216
net.ipv4.tcp_wmem=4096 65536 16777216
net.ipv4.tcp_congestion_control=bbr
net.ipv4.tcp_mtu_probing=1
net.ipv4.tcp_fastopen=3
# Memory optimizations
vm.swappiness=10
vm.dirty_ratio=10
vm.dirty_background_ratio=5
vm.vfs_cache_pressure=50
# File descriptor limits
fs.file-max=2097152
fs.nr_open=2097152
EOF

# Apply sysctl settings
sysctl -p /etc/sysctl.d/99-performance.conf

# Update GRUB with kernel parameters
log "Updating GRUB configuration"
[[ -f /etc/default/grub ]] && cp /etc/default/grub "$BACKUP_DIR/"
if ! grep -q "mitigations=off" /etc/default/grub; then
    sed -i 's/GRUB_CMDLINE_LINUX_DEFAULT="quiet"/GRUB_CMDLINE_LINUX_DEFAULT="quiet splash mitigations=off elevator=none transparent_hugepage=always"/' /etc/default/grub
    update-grub
else
    log "GRUB already configured with performance parameters"
fi

# CPU governor configuration
apt-get install -y cpufrequtils
cat > /etc/default/cpufrequtils << 'EOF'
GOVERNOR="performance"
EOF

# Entropy configuration
apt-get install -y rng-tools
cat > /etc/default/rng-tools << 'EOF'
HRNGDEVICE=/dev/urandom
RNGDOPTIONS="--rng-driver=kernel --fill-watermark=90% --feed-interval=1"
EOF

# ZRAM configuration
apt-get install -y zram-tools
cat > /etc/zram.conf << 'EOF'
ZRAM_SIZE=8192
ZRAM_COMP_ALGORITHM=lz4
ZRAM_SWAPPINESS=100
EOF

# Tuned installation and configuration
apt-get install -y tuned python3 python3-configobj python3-decorator python3-pyudev python3-linux-procfs python3-schedutils virt-what
systemctl enable tuned
tuned-adm profile throughput-performance

# Additional performance tools
apt-get install -y preload irqbalance htop

# SSH configuration
log "Configuring SSH server"
apt-get install -y openssh-server

cat > /etc/ssh/sshd_config.d/custom.conf << 'EOF'
Port 51599
PermitRootLogin yes
X11Forwarding no
EOF

mkdir -p /etc/ssh/sshd_config.d
cat > /etc/ssh/sshd_config.d/performance.conf << 'EOF'
UseDNS no
TCPKeepAlive yes
ClientAliveInterval 300
ClientAliveCountMax 3
EOF

# NFS server configuration
log "Installing and configuring NFS server"
apt-get install -y nfs-kernel-server rpcbind

cat > /etc/exports << 'EOF'
/home/heimdall 192.168.1.0/24(rw,sync,no_subtree_check)
EOF

cat > /etc/nfs.conf << 'EOF'
[nfsd]
threads=16
tcp=y
vers3=n
vers4=y
EOF

# Firewall configuration
log "Configuring nftables firewall"
apt-get install -y nftables

cat > /etc/nftables.conf << 'EOF'
#!/usr/sbin/nft -f
flush ruleset
table inet filter {
  chain input {
    type filter hook input priority 0; policy drop;
    iif lo accept
    ct state established,related accept
    tcp dport 51599 accept
    udp dport 53 ip saddr 192.168.1.0/24 accept
    tcp dport 53 ip saddr 192.168.1.0/24 accept
    tcp dport {2049, 111, 32765-32769} ip saddr 192.168.1.0/24 accept
    udp dport {2049, 111, 32765-32769} ip saddr 192.168.1.0/24 accept
    tcp dport {6443, 10250, 80, 443, 3000} accept
    log prefix "nftables-dropped: " limit rate 5/minute
    drop
  }
  chain forward {
    type filter hook forward priority 0; policy drop;
  }
  chain output {
    type filter hook output priority 0; policy accept;
  }
}
EOF

# Kubernetes (k3s) installation
log "Installing Kubernetes (k3s)"
apt-get install -y iptables conntrack libnetfilter-conntrack3 ethtool socat bridge-utils

# Install k3s
if ! command -v k3s &> /dev/null; then
    curl -sfL https://get.k3s.io | sh -
    log "k3s installed successfully"
else
    log "k3s already installed, skipping installation"
fi

# Install kubectl
if ! command -v kubectl &> /dev/null; then
    curl -LO "https://dl.k8s.io/release/$(curl -L -s https://dl.k8s.io/release/stable.txt)/bin/linux/amd64/kubectl"
    chmod +x kubectl
    mv kubectl /usr/local/bin/
    log "kubectl installed successfully"
else
    log "kubectl already installed, skipping installation"
fi

# K3s performance configuration
mkdir -p /etc/rancher/k3s
cat > /etc/rancher/k3s/config.yaml << 'EOF'
kube-apiserver-arg:
  - "max-requests-inflight=1000"
  - "max-mutating-requests-inflight=500"
kubelet-arg:
  - "max-pods=250"
  - "cpu-manager-policy=static"
EOF

# Install and configure nginx
apt-get install -y nginx
cat > /etc/nginx/nginx.conf << 'EOF'
worker_processes auto;
worker_rlimit_nofile 65535;
events {
  worker_connections 2048;
  multi_accept on;
}
http {
  sendfile on;
  tcp_nopush on;
  tcp_nodelay on;
  keepalive_timeout 65;
  types_hash_max_size 2048;
  server_tokens off;
  gzip on;
  gzip_types text/plain text/css application/json application/javascript;
  proxy_cache_path /var/cache/nginx levels=1:2 keys_zone=my_cache:10m max_size=10g inactive=60m use_temp_path=off;
  include /etc/nginx/mime.types;
  default_type application/octet-stream;
  include /etc/nginx/conf.d/*.conf;
  include /etc/nginx/sites-enabled/*;
}
EOF

# Container development with Podman
log "Installing Podman for container development"
apt-get install -y podman fuse-overlayfs conmon crun slirp4netns uidmap

cat > /etc/containers/storage.conf << 'EOF'
[storage]
driver = "overlay"
[storage.options]
mount_program = "/usr/bin/fuse-overlayfs"
EOF

# Configure rootless storage for heimdall
mkdir -p /home/heimdall/.config/containers
cat > /home/heimdall/.config/containers/storage.conf << 'EOF'
[storage]
driver = "overlay"
[storage.options]
mount_program = "/usr/bin/fuse-overlayfs"
EOF
chown -R heimdall:heimdall /home/heimdall/.config

# Git server (Gitea) setup
log "Setting up Gitea git server"

# Install Redis for Gitea caching
apt-get install -y redis-server redis-tools

cat > /etc/redis/redis.conf << 'EOF'
maxmemory 256mb
maxmemory-policy allkeys-lru
save ""
appendonly yes
appendfsync everysec
bind 127.0.0.1
port 6379
EOF

# Create Gitea directories
mkdir -p /var/lib/gitea/data
mkdir -p /var/lib/gitea/custom/conf

# Download Gitea binary
if [[ ! -f /usr/local/bin/gitea ]]; then
    wget -O /usr/local/bin/gitea https://dl.gitea.io/gitea/1.22.2/gitea-1.22.2-linux-amd64
    chmod +x /usr/local/bin/gitea
    log "Gitea binary downloaded successfully"
else
    log "Gitea binary already exists, skipping download"
fi

# Create Gitea K3s pod configuration
cat > /tmp/gitea-pod.yaml << 'EOF'
apiVersion: v1
kind: Pod
metadata:
  name: gitea
  namespace: default
spec:
  containers:
  - name: gitea
    image: gitea/gitea:1.22.2
    ports:
    - containerPort: 3000
    volumeMounts:
    - name: gitea-data
      mountPath: /data
  volumes:
  - name: gitea-data
    hostPath:
      path: /var/lib/gitea
EOF

# Gitea configuration
cat > /var/lib/gitea/custom/conf/app.ini << 'EOF'
[server]
HTTP_PORT = 3000
DISABLE_SSH = false
[database]
DB_TYPE = sqlite3
PATH = /var/lib/gitea/data/gitea.db
CACHE_MODE = redis
[cache]
ADAPTER = redis
HOST = redis://localhost:6379/0
[session]
PROVIDER = redis
PROVIDER_CONFIG = redis://localhost:6379/0
[queue]
TYPE = redis
CONN_STR = redis://localhost:6379/0
EOF

# Enable and start services
log "Enabling and starting services"
systemctl enable dnsmasq
systemctl enable ssh
systemctl enable nfs-kernel-server
systemctl enable nftables
systemctl enable k3s
systemctl enable nginx
systemctl enable redis-server
systemctl enable rng-tools
systemctl enable tuned
systemctl enable preload
systemctl enable irqbalance

# Wait for k3s to be ready before applying Gitea pod
log "Waiting for k3s to be ready..."
for i in {1..12}; do
    if kubectl get nodes &>/dev/null; then
        log "k3s is ready"
        break
    fi
    if [[ $i -eq 12 ]]; then
        warn "k3s may not be fully ready, continuing anyway"
    fi
    sleep 10
done

# Apply Gitea pod to k3s
if ! kubectl get pod gitea &>/dev/null; then
    kubectl apply -f /tmp/gitea-pod.yaml
    log "Gitea pod applied to k3s"
else
    log "Gitea pod already exists in k3s"
fi

# Start services
log "Starting services"
systemctl start dnsmasq
systemctl start ssh
systemctl start nfs-kernel-server
systemctl start nftables
systemctl start nginx
systemctl start redis-server
systemctl start rng-tools
systemctl start tuned
systemctl start preload
systemctl start irqbalance

# Export NFS shares
exportfs -a

# Final network restart
log "Restarting networking"
systemctl restart networking

log "Post-install configuration completed successfully!"

# Verify critical services
log "Verifying critical services..."
FAILED_SERVICES=()

for service in dnsmasq ssh nfs-kernel-server nftables nginx redis-server; do
    if ! systemctl is-active --quiet $service; then
        FAILED_SERVICES+=($service)
    fi
done

if [[ ${#FAILED_SERVICES[@]} -gt 0 ]]; then
    warn "Some services failed to start: ${FAILED_SERVICES[*]}"
    warn "Check logs with: journalctl -u <service_name>"
else
    log "All critical services are running successfully!"
fi

log "System will need a reboot to apply all kernel parameters and performance tweaks."

warn "Important notes:"
echo "1. SSH is now running on port 51599"
echo "2. Gitea will be available at http://192.168.1.120:3000 after k3s pod starts"
echo "3. NFS share: /home/heimdall available to 192.168.1.0/24 network"
echo "4. DNS server running on 127.0.0.1 and 192.168.1.120"
echo "5. Wildcard domains: *.dev, *.test, *.star -> 192.168.1.120"
echo ""
echo "Configuration backups stored in: $BACKUP_DIR"
echo "Run 'systemctl reboot' to restart the system and apply all changes."
