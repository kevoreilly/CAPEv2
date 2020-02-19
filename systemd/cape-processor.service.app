[Unit]
Description=Cuckoo report processor
Documentation=https://github.com/kevoreilly/CAPEv2
Wants=cuckoo-rooter.service
After=cuckoo-rooter.service

[Service]
WorkingDirectory=/opt/CAPE/utils/
ExecStart=/usr/bin/python process.py -p7 auto
#ExecStart=/opt/CAPE/venv/bin/python3 /opt/CAPE/utils/process.py -p7 auto
User=cuckoo
Group=cuckoo
Restart=always
RestartSec=5m

[Install]
WantedBy=multi-user.target
