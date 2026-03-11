export const CLOUD_INIT_SCRIPT = `#!/bin/bash
# OriClaw auto-provisioning script
set -e

# Update system
apt-get update -y
apt-get upgrade -y

# Install Node.js 20
curl -fsSL https://deb.nodesource.com/setup_20.x | bash -
apt-get install -y nodejs git curl wget

# Install OpenClaw globally
npm install -g openclaw

# Create openclaw user
useradd -m -s /bin/bash openclaw || true

# Setup OpenClaw as service
cat > /etc/systemd/system/openclaw.service << 'SERVICEEOF'
[Unit]
Description=OpenClaw AI Assistant
After=network.target

[Service]
Type=simple
User=openclaw
WorkingDirectory=/home/openclaw
ExecStart=/usr/local/bin/openclaw gateway start
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
SERVICEEOF

systemctl daemon-reload
systemctl enable openclaw
systemctl start openclaw

# Signal completion
echo "ORICLAW_READY" > /var/lib/cloud/instance/oriclaw-status
`;
