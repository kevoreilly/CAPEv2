# systemd service units

These files help run all the various parts of CAPE as systemd services, so that they start in the proper order, and will restart in the event of a crash.

- `cape-rooter.service` - Runs `rooter.py`
- `cape-processor.service` - Runs `process.py`
- `cape.service` - Runs `cuckoo.py`
- `cape-web.service` - Runs the CAPE web interface via Granian (WSGI) with `conf/cape-web.env` overrides and zero-downtime `systemctl reload cape-web` (`SIGHUP`)
- `guac-web.service` - Runs the Guacamole WebSocket/ASGI app via Granian (ASGI) on `127.0.0.1:8008` with `conf/guac-web.env` overrides
- `00-ignore-vnet.network` - Marks ephemeral guest VM/bridge interfaces (`vnet*`, `virbr*`, `tap*`) as unmanaged in `systemd-networkd` to prevent DHCP renewal timeouts on the primary host interface

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

1. Install `uv` and a shared managed Python 3.14 runtime (see [Poetry to uv Migration Guide](../docs/book/src/installation/uv_migration.rst) if upgrading an existing Poetry host):

   ```bash
   curl -LsSf https://astral.sh/uv/install.sh | sudo env UV_INSTALL_DIR=/usr/local/bin sh
   sudo env UV_PYTHON_INSTALL_DIR=/usr/local/share/uv/python /usr/local/bin/uv python install 3.14
   sudo chmod -R a+rX /usr/local/share/uv/python
   ```

2. Place CAPEv2 in `/opt/CAPEv2`
3. Ensure the `CAPEv2` directory is owned by the `cape` user

    ```bash
    sudo chown cape:cape -R /opt/CAPEv2
    ```

4. Sync dependencies into `/opt/CAPEv2/.venv` as the `cape` user

    ```bash
    cd /opt/CAPEv2
    sudo -Hu cape env UV_PYTHON_INSTALL_DIR=/usr/local/share/uv/python /usr/local/bin/uv sync --locked --no-install-project --inexact --python 3.14
    ```

5. Edit configuration files in `/opt/CAPEv2/conf` as needed

6. Install the `systemd` service unit configuration files (all Python units invoke `/usr/local/bin/uv run --no-sync` against `/opt/CAPEv2/.venv`):

    ```bash
    sudo cp /opt/CAPEv2/systemd/*.service /etc/systemd/system
    sudo cp /opt/CAPEv2/systemd/*.timer /etc/systemd/system
    sudo mkdir -p /etc/systemd/network
    sudo cp /opt/CAPEv2/systemd/00-ignore-vnet.network /etc/systemd/network/
    sudo networkctl reload
    sudo systemctl daemon-reload
    sudo systemctl enable suricata-update.service
    sudo systemctl enable suricata-update.timer
    sudo systemctl enable cape-rooter.service
    sudo systemctl enable cape-processor.service
    sudo systemctl enable cape.service
    sudo systemctl enable cape-web.service
    ```

7. Start the services for the first time

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
