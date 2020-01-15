# systemd service units

These files help run all the various parts of CAPE as systemd services, so that they start in the proper order, and will restart in the event of a crash.

- `cuckoo-rooter.service` - Runs `rooter.py`
- `cuckoo-processor.service` - Runs `process.py`
- `cuckoo.service` - Runs `cuckoo.py`
- `cuckoo-wsgi.service` - Runs the Cuckoo web interface as a WSGI application using Gunicorn bound to `127.0.0.1:8000`

## Setup
0. You need to edit the default values in systemd to not get `too many open files`

/etc/systemd/user.conf
    DefaultLimitNOFILE=1048576

/etc/systemd/system.conf
    DefaultLimitNOFILE=2097152

* to verify changes 
    ```bash 
        systemctl show cuckoo-processor|grep LimitNOFILE #replace cuckoo-processor with another systemd daemon after install them all
    ```

1. (optional) Install virtualenv

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

5. (optional) Create a virtualenv at `/opt/CAPE/venv`

    ```bash
    virtualenv /opt/CAPE/venv
    ```

6. (optional) Install required Python packages inside the virtualenv
    * dependencies now installed by https://github.com/doomedraven/Tools/blob/master/Cuckoo/cuckoo3.sh

7. Edit configuration files in `/opt/CAPE/conf` as needed
8. Return to your user

    ```bash
    exit
    ```

9. Install the `systemd` service unit configuration files(you need modify ExecStart= if you using virtualenv, just comment current one and uncomment another one)

    ```bash
    sudo cp /opt/CAPE/systemd/*.service /etc/systemd/system
    sudo cp /opt/CAPE/systemd/*.timer /etc/systemd/system
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
    sudo systemctl start suricata-update.service
    sudo systemctl start cuckoo-rooter.service
    sudo systemctl start cuckoo-processor.service
    sudo systemctl start cuckoo.service
    sudo systemctl start cuckoo-wsgi.service
    ```

## Troubleshooting

To view the status and console output of a service:

```bash
sudo systemctl status cuckoo
```

To view the full output of a service (including crashed services):

```bash
journalctl -u cuckoo-wsgi.service -r
```

Note: The `journalctl -r` switch displays the log lines in reverse order, with the newest lines on top.
