#!/bin/bash

# Install dependencies
sudo apt update
sudo apt install build-essential curl net-tools python3-pip python3-pyinotify systemtap-runtime ca-certificates curl gnupg lsb-release -y

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

#tracee
sudo install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
sudo chmod a+r /etc/apt/keyrings/docker.gpg
echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu $(. /etc/os-release && echo $VERSION_CODENAME) stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
sudo apt-get update
sudo apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
sudo systemctl enable --now docker
sudo docker pull docker.io/aquasec/tracee:0.24.1
sudo docker image tag docker.io/aquasec/tracee:0.24.1 aquasec/tracee:latest
