#!/bin/bash

# Install dependencies
sudo apt update
sudo apt install build-essential curl net-tools python3-pip -y
sudo pip3 install pyinotify

# agent.py installation
sudo mkdir /root/.cape
sudo wget https://raw.githubusercontent.com/kevoreilly/CAPEv2/master/agent/agent.py -O /root/.cape/agent.py 
sudo sed -i '36,37 s/^/# /' /root/.cape/agent.py
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
