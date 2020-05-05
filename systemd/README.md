# systemd service units

These files help run all the various parts of CAPE as systemd services, so that they start in the proper order, and will restart in the event of a crash.

- `cape-rooter.service` - Runs `rooter.py`
- `cape-processor.service` - Runs `process.py`
- `cape.service` - Runs `cuckoo.py`
- `cape-web.service` - Runs the Cuckoo web interface as a WSGI application using Gunicorn bound to `127.0.0.1:8000`

## Setup
0. You need to edit the default values in systemd to not get `too many open files`

    ```bash
    sudo sed -i "s/#DefaultLimitNOFILE=/DefaultLimitNOFILE=1048576/g" /etc/systemd/user.conf
    sudo sed -i "s/#DefaultLimitNOFILE=/DefaultLimitNOFILE=1048576/g" /etc/systemd/system.conf
    ```

* to verify changes

    ```bash
    #replace cape-processor with another systemd daemon after install them all
    systemctl show cape-processor | grep LimitNOFILE
    ```

1. (optional) Install virtualenv

   ```bash
   sudo apt-get install -y python3-virtualenv
   ```

2. Place CAPEv2 in `/opt/CAPEv2`
3. Ensure the `CAPEv2` directory is owned by the `cape` user

    ```bash
    sudo chown cape:cape -R /opt/CAPEv2
    ```

4. Switch to the cape user

    ```bash
    sudo su cape
    ```

5. (optional) Create a virtualenv at `/opt/CAPEv2/venv`

    ```bash
    virtualenv /opt/CAPEv2/venv
    ```

6. (optional) Install required Python packages inside the virtualenv
    * dependencies now installed by https://github.com/doomedraven/Tools/blob/master/Sandbox/cape2.sh

7. Edit configuration files in `/opt/CAPEv2/conf` as needed
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
    sudo systemctl enable cape-rooter.service
    sudo systemctl enable cape-processor.service
    sudo systemctl enable cape.service
    sudo systemctl enable cape-web.service
    ```

10. Start the services for the first time

    ```bash
    sudo systemctl start suricata-update.service
    sudo systemctl start cape-rooter.service
    sudo systemctl start cape-processor.service
    sudo systemctl start cape.service
    sudo systemctl start cape-web.service
    ```

## Troubleshooting

To view the status and console output of a service:

```bash
sudo systemctl status cape
```

To view the full output of a service (including crashed services):

```bash
journalctl -u cape-web.service -r
```

Note: The `journalctl -r` switch displays the log lines in reverse order, with the newest lines on top.
