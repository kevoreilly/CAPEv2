# systemd service units

These files help run all the various parts of CAPE as systemd services, so that they start in the proper order, and will restart in the event of a crash.

- `cuckoo-rooter.service` - Runs `rooter.py`
- `cuckoo-processor.service` - Runs `process.py`
- `cuckoo.service` - Runs `cuckoo.py`
- `cuckoo-wsgi.service` - Runs the Cuckoo web interface as a WSGI application using Gunicorn bound to `127.0.0.1:8000`

## Setup

1. Install virtualenv

   ```bash
   sudo apt-get install -y python3-virtualenv
   ```

2. Place CAPE in `/opt/CAPE`
3. Ensure the `CAPE` directory is owned by the `cuckoo` user

    ```bash
    sudo chown cuckoo:cuckoo -R /opt/CAPE
    ```

4. Switch to the cuckoo user

    ```bash
    sudo su cuckoo
    ```

5. Create a virtualenv at `/opt/CAPE/venv`

    ```bash
    virtualenv /opt/CAPE/venv
    ```

6. Install required Python packages inside the virtualenv

    ```bash
    /opt/CAPE/venv/bin/pip3 install -U -r /opt/CAPE/requirements.txt
    ```

7. Edit configuration files in `/opt/CAPE/conf` as needed
8. Return to your user

    ```bash
    exit
    ```

9. Install the `systemd` service unit configuration files

    ```bash
    sudo cp /opt/CAPE/systemd/*.service /opt/systemd/system
    sudo cp /opt/CAPE/systemd/*.timer /opt/systemd/system
    sudo sudo systemctl daemon-reload
    sudo systemctl enable suricata-update.service
    sudo systemctl enable suricata-update.timer
    sudo systemctl enable cuckoo-rooter.service
    sudo systemctl enable cuckoo-processor.service
    sudo systemctl enable cuckoo.service
    sudo systemctl enable cuckoo-wsgi.service
    ```

10. Start the services for the first time

    ```bash
    sudo service suricata-update start
    sudo service cuckoo-rooter start
    sudo service cuckoo-processor start
    sudo service cuckoo start
    sudo service cuckoo-wsgi start
    ```

## Troubleshooting

To view the status and console output of a service:

```bash
service cuckoo status
```

To view the full output of a service (including crashed services):

```bash
journalctl -u cuckoo-wsgi.service -r
```

Note: The `journalctl -r` switch displays the log lines in reverse order, with the newest lines on top.
