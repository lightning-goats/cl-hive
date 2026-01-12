# cl-hive Docker Deployment

Production-ready Docker image for cl-hive Lightning nodes with Tor, WireGuard, and full plugin stack.

## Features

- **Core Lightning** v25+ with all plugins
- **Tor** hidden service for privacy
- **WireGuard** VPN support (optional)
- **CLBOSS** for automated channel management
- **cl-revenue-ops** for fee optimization
- **cl-hive** for fleet coordination
- **sling** for rebalancing

## Quick Start

### 1. Configure Environment

```bash
cd docker
cp .env.example .env
```

Edit `.env` with your Bitcoin RPC credentials:

```bash
BITCOIN_RPCHOST=192.168.1.100
BITCOIN_RPCPORT=8332
BITCOIN_RPCUSER=myuser
BITCOIN_RPCPASSWORD=mypassword
ALIAS=my-hive-node
```

### 2. Build and Start

```bash
docker-compose up -d
```

### 3. Check Status

```bash
# View logs
docker-compose logs -f

# Check node info
docker-compose exec cln lightning-cli getinfo

# Check hive status
docker-compose exec cln lightning-cli hive-status
```

## Configuration Options

### Environment Variables

#### Core Settings

| Variable | Default | Description |
|----------|---------|-------------|
| `BITCOIN_RPCHOST` | `127.0.0.1` | Bitcoin RPC host |
| `BITCOIN_RPCPORT` | `8332` | Bitcoin RPC port |
| `BITCOIN_RPCUSER` | - | Bitcoin RPC username (required) |
| `BITCOIN_RPCPASSWORD` | - | Bitcoin RPC password (required) |
| `NETWORK` | `bitcoin` | Network: bitcoin, testnet, signet, regtest |
| `ALIAS` | `cl-hive-node` | Node alias |
| `RGB` | `FF9900` | Node color (hex) |
| `ANNOUNCE_ADDR` | - | Public address to announce |
| `TOR_ENABLED` | `true` | Enable Tor hidden service |
| `WIREGUARD_ENABLED` | `false` | Enable WireGuard VPN |
| `CLBOSS_ENABLED` | `true` | Enable CLBOSS |
| `HIVE_GOVERNANCE_MODE` | `advisor` | Hive governance mode |
| `LOG_LEVEL` | `info` | Log level |

#### WireGuard Settings (when `WIREGUARD_ENABLED=true`)

| Variable | Default | Description |
|----------|---------|-------------|
| `WG_PRIVATE_KEY` | - | Your WireGuard private key (required) |
| `WG_ADDRESS` | `10.0.0.2/24` | Your VPN IP address |
| `WG_DNS` | - | DNS server through VPN (optional) |
| `WG_PEER_PUBLIC_KEY` | - | VPN server's public key (required) |
| `WG_PEER_ENDPOINT` | - | VPN server endpoint (host:port) |
| `WG_PEER_ALLOWED_IPS` | `0.0.0.0/0` | IPs to route through VPN |
| `WG_PEER_KEEPALIVE` | `25` | Keepalive interval (seconds)

### Volumes

| Path | Description |
|------|-------------|
| `/data/lightning` | Lightning node data (persistent) |
| `/etc/wireguard` | WireGuard configuration |
| `/etc/lightning/custom` | Custom configuration files |

## Tor Configuration

Tor is enabled by default. The hidden service address is created on first start.

### Get Tor Address

```bash
docker-compose exec cln cat /var/lib/tor/cln-service/hostname
```

### Disable Tor

Set in `.env`:
```
TOR_ENABLED=false
ANNOUNCE_ADDR=your.public.ip:9735
```

## WireGuard Configuration

WireGuard can be used to securely connect to your bitcoind backend over a VPN tunnel.

### Option 1: Environment Variables (Recommended)

Set in `.env`:
```bash
WIREGUARD_ENABLED=true

# Generate a private key: wg genkey
WG_PRIVATE_KEY=your_private_key_here

# Your VPN IP (assigned by VPN provider)
WG_ADDRESS=10.0.0.2/24

# VPN server details
WG_PEER_PUBLIC_KEY=server_public_key_here
WG_PEER_ENDPOINT=vpn.example.com:51820

# Route only bitcoind traffic through VPN (more efficient)
# Replace with your bitcoind server's IP
WG_PEER_ALLOWED_IPS=192.168.1.100/32

# Or route all traffic through VPN
# WG_PEER_ALLOWED_IPS=0.0.0.0/0

WG_PEER_KEEPALIVE=25
```

### Option 2: Mount Config File

Create `wireguard/wg0.conf`:

```ini
[Interface]
PrivateKey = <your-private-key>
Address = 10.0.0.2/24

[Peer]
PublicKey = <server-public-key>
Endpoint = vpn.example.com:51820
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = 25
```

Set in `.env`:
```
WIREGUARD_ENABLED=true
WIREGUARD_CONFIG_PATH=./wireguard
```

### Using WireGuard with Bitcoin RPC

To connect to bitcoind through the VPN:

```bash
# In .env, set BITCOIN_RPCHOST to the bitcoind IP on the VPN network
BITCOIN_RPCHOST=10.0.0.1

# Route only that IP through WireGuard
WG_PEER_ALLOWED_IPS=10.0.0.1/32
```

## Hive Operations

### Initialize Genesis (First Node)

```bash
docker-compose exec cln lightning-cli hive-genesis "my-hive-name"
```

### Generate Invite

```bash
docker-compose exec cln lightning-cli hive-invite 24
```

### Join Existing Hive

```bash
docker-compose exec cln lightning-cli hive-join "HIVE1-INVITE-..."
```

### Check Members

```bash
docker-compose exec cln lightning-cli hive-members
```

## Backup and Restore

### Backup

```bash
# Stop container
docker-compose stop

# Backup data volume
docker run --rm -v cl-hive_lightning-data:/data -v $(pwd):/backup \
  ubuntu tar cvf /backup/lightning-backup.tar /data

# Restart
docker-compose start
```

### Restore

```bash
# Stop container
docker-compose stop

# Restore data volume
docker run --rm -v cl-hive_lightning-data:/data -v $(pwd):/backup \
  ubuntu tar xvf /backup/lightning-backup.tar -C /

# Restart
docker-compose start
```

## Monitoring

### View Logs

```bash
# All logs
docker-compose logs -f

# Lightning only
docker-compose logs -f cln | grep lightningd

# Hive plugin
docker-compose logs -f cln | grep cl-hive
```

### Health Check

```bash
docker-compose exec cln lightning-cli getinfo
docker-compose exec cln lightning-cli hive-status
docker-compose exec cln lightning-cli revenue-status
```

## Updating

```bash
# Pull latest changes
git pull

# Rebuild image
docker-compose build --no-cache

# Restart with new image
docker-compose up -d
```

## Troubleshooting

### Bitcoin RPC Connection Failed

1. Check Bitcoin Core is running and RPC is enabled
2. Verify RPC credentials in `.env`
3. Check network connectivity:
   ```bash
   docker-compose exec cln curl -u $BITCOIN_RPCUSER:$BITCOIN_RPCPASSWORD \
     http://$BITCOIN_RPCHOST:$BITCOIN_RPCPORT
   ```

### Tor Hidden Service Not Created

1. Check Tor logs:
   ```bash
   docker-compose exec cln cat /var/log/tor/notices.log
   ```
2. Verify permissions on Tor directory

### Bridge Disabled

```bash
# Reinitialize bridge
docker-compose exec cln lightning-cli hive-reinit-bridge
```

### Plugin Not Loading

```bash
# Check plugin list
docker-compose exec cln lightning-cli plugin list

# Check plugin logs
docker-compose logs cln | grep -i error
```

## Security Considerations

1. **Protect `.env` file** - Contains RPC credentials
2. **Backup hsm_secret** - Located in `/data/lightning/*/hsm_secret`
3. **Use Tor** - Recommended for privacy
4. **Firewall** - Only expose necessary ports
5. **Updates** - Keep image updated for security fixes

## Building Custom Image

```bash
# Build with custom tag
docker build -t my-registry/cl-hive-node:v1.0 -f docker/Dockerfile .

# Push to registry
docker push my-registry/cl-hive-node:v1.0
```

## Multi-Node Deployment

For running multiple hive nodes, create separate compose files:

```bash
# node1.yml
cp docker-compose.yml docker-compose.node1.yml
# Edit with unique ALIAS, ports, volumes

# Start
docker-compose -f docker-compose.node1.yml up -d
```

Or use Docker Swarm / Kubernetes for orchestration.
