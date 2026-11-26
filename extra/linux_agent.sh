#!/bin/bash

# Install dependencies
sudo apt update
sudo apt install build-essential curl net-tools python3-pip python3-pyelftools systemtap-runtime ca-certificates gnupg 7zip nodejs default-jre apt-transport-https software-properties-common lsb-release -y
# unrar is in multiverse/non-free on Ubuntu/Debian; install best-effort without aborting core setup
sudo apt install -y unrar || sudo apt install -y unrar-free || true
if [ "$(python3 -c 'import sys; print(1 if sys.version_info > (3, 11) else 0)')" -eq "1" ]; then
  sudo apt install -y python3-setuptools
fi
source /etc/os-release
if [ -n "${ID:-}" ] && [ -n "${VERSION_ID:-}" ]; then
  MS_DEB="$(mktemp /tmp/packages-microsoft-prod.XXXXXX.deb)"
  if wget -q "https://packages.microsoft.com/config/${ID}/${VERSION_ID}/packages-microsoft-prod.deb" -O "$MS_DEB"; then
    sudo dpkg -i "$MS_DEB" && sudo apt update && sudo apt install -y powershell || true
  fi
  rm -f "$MS_DEB"
fi

# agent.py installation
sudo mkdir /root/.cape
sudo wget https://raw.githubusercontent.com/kevoreilly/CAPEv2/master/agent/agent.py -O /root/.cape/agent.py
sudo crontab -l | { cat; echo "@reboot python3 /root/.cape/agent.py"; } | sudo crontab -

# Disable firewall and NTP
sudo ufw disable
sudo timedatectl set-ntp off

# Disable auto-update for noise reduction
sudo tee /etc/apt/apt.conf.d/20auto-upgrades << EOF
APT::Periodic::Update-Package-Lists "0";
APT::Periodic::Download-Upgradeable-Packages "0";
APT::Periodic::AutocleanInterval "0";
APT::Periodic::Unattended-Upgrade "0";
EOF

sudo systemctl stop snapd.service && sudo systemctl mask snapd.service
