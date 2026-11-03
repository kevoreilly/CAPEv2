#!/bin/bash

# Install dependencies
sudo apt update
sudo apt install build-essential curl net-tools python3-pip python3-pyinotify python3-pyelftools systemtap-runtime ca-certificates curl gnupg 7zip unrar nodejs default-jre apt-transport-https software-properties-common lsb-release -y
if [ "$(python3 -c 'import sys; print(1 if sys.version_info > (3, 11) else 0)')" -eq "1" ]; then
  sudo apt install -y python3-pyasyncore python3-setuptools
fi
source /etc/os-release
wget -q https://packages.microsoft.com/config/ubuntu/$VERSION_ID/packages-microsoft-prod.deb
sudo dpkg -i packages-microsoft-prod.deb
rm packages-microsoft-prod.deb
sudo apt update
sudo apt install -y powershell

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
