"use strict";

const KEYSYM = {
    SHIFT:   0xFFE1,
    CTRL:    0xFFE3,
    INSERT:  0xFF63,
    V_UPPER: 0x0056,
    V_LOWER: 0x0076,
};

const PASTE_COMPONENT_KEYS = new Set([
    KEYSYM.SHIFT, KEYSYM.CTRL, KEYSYM.INSERT,
    KEYSYM.V_UPPER, KEYSYM.V_LOWER,
]);

const PASTE_DELAY_MS = 50;

const NON_FATAL_STATUS_CODES = new Set([0, 256]);

const ICON_ERROR = 'fas fa-exclamation-circle text-danger';
const ICON_WARNING = 'fas fa-exclamation-triangle text-warning';
const ICON_SUCCESS = 'fas fa-check-circle text-success';

class GuacSession {
    constructor(element, config) {
        this.config = config;
        this.client = null;
        this.tunnel = null;
        this.display = null;
        this.keyboard = null;
        this.connected = false;
        this.ctrl = false;
        this.shift = false;
        this.dialogContainer = $(element).find('.guaconsole')[0];

        this._init();
    }

    _buildWsUrl() {
        return location.origin.replace(/^http(s?):/, (match, p1) =>
            p1 ? 'wss:' : 'ws:'
        );
    }

    _isPasteShortcut(keysym) {
        return (this.ctrl && this.shift && keysym === KEYSYM.V_UPPER)
            || (this.ctrl && keysym === KEYSYM.V_LOWER)
            || (this.shift && keysym === KEYSYM.INSERT);
    }

    _init() {
        const wsUrl = this._buildWsUrl();
        this.tunnel = new Guacamole.WebSocketTunnel(
            wsUrl + '/guac/websocket-tunnel/' + this.config.session_id
        );
        this.client = new Guacamole.Client(this.tunnel);

        this.connect();

        this.display = this.client.getDisplay().getElement();
        $('#terminal').append(this.display);

        this._setupScaling();

        window.onunload = () => this.disconnect();

        this._setupMouse();
        this._setupKeyboard();
        this._setupClipboard();
        this._setupErrorHandler();
    }

    _setupScaling() {
        const scaleDisplay = () => {
            var display = this.client.getDisplay();
            var displayWidth = display.getWidth();
            var displayHeight = display.getHeight();
            if (!displayWidth || !displayHeight) return;

            var container = document.getElementById('container');
            var containerWidth = container.offsetWidth;
            var containerHeight = container.offsetHeight;
            if (!containerWidth || !containerHeight) return;

            var scale = Math.min(
                containerWidth / displayWidth,
                containerHeight / displayHeight
            );
            display.scale(scale);
        };

        this.client.getDisplay().onresize = function() {
            scaleDisplay();
        };

        var resizeTimeout;
        window.addEventListener('resize', function() {
            clearTimeout(resizeTimeout);
            resizeTimeout = setTimeout(scaleDisplay, 100);
        });
    }

    _setupMouse() {
        const mouse = new Guacamole.Mouse(this.display);
        const sendState = (state) => this.client.sendMouseState(state, true);
        mouse.onmousedown = sendState;
        mouse.onmouseup   = sendState;
        mouse.onmousemove = sendState;
    }

    _setupKeyboard() {
        this.keyboard = new Guacamole.Keyboard(this.display);

        this.keyboard.onkeydown = (keysym) => {
            if (keysym === KEYSYM.SHIFT)  this.shift = true;
            else if (keysym === KEYSYM.CTRL) this.ctrl = true;

            if (this._isPasteShortcut(keysym)) {
                setTimeout(() => this.client.sendKeyEvent(1, keysym), PASTE_DELAY_MS);
            } else {
                this.client.sendKeyEvent(1, keysym);
            }

            return !PASTE_COMPONENT_KEYS.has(keysym);
        };

        this.keyboard.onkeyup = (keysym) => {
            if (keysym === KEYSYM.SHIFT)  this.shift = false;
            else if (keysym === KEYSYM.CTRL) this.ctrl = false;

            if (this._isPasteShortcut(keysym)) {
                setTimeout(() => this.client.sendKeyEvent(0, keysym), PASTE_DELAY_MS);
            } else {
                this.client.sendKeyEvent(0, keysym);
            }
        };

        $(this.display)
            .attr('tabindex', 1)
            .hover(
                function () {
                    const x = window.scrollX, y = window.scrollY;
                    $(this).focus();
                    window.scrollTo(x, y);
                },
                function () { $(this).blur(); }
            )
            .blur(() => this.keyboard.reset());
    }

    _setupClipboard() {
        $(document).on('paste', (e) => {
            const text = e.originalEvent.clipboardData.getData('text/plain');
            if ($(this.display).is(':focus')) {
                this.client.setClipboard(text);
            }
        });
    }

    _showDialog(title, detail, icon) {
        const dialog = $('#launch_error');
        const iconHtml = icon ? `<i class="${icon} me-1"></i>` : '';
        dialog.find('#dialog-heading').html(`${iconHtml}${title}`);
        dialog.find('#dialog-message').html(detail);
        dialog.dialog({ dialogClass: 'no-close' });
        dialog.dialog(this.dialogContainer);
    }

    _showError(title, detail) {
        this._showDialog(title, detail, ICON_ERROR);
    }

    _showWarning(title, detail) {
        this._showDialog(title, detail, ICON_WARNING);
    }

    _showSuccess(title, detail) {
        this._showDialog(title, detail, ICON_SUCCESS);
    }

    _setupErrorHandler() {
        const handler = (error) => {
            console.log(`guac error ${error.code}: ${error.message}`);

            if (NON_FATAL_STATUS_CODES.has(error.code)) {
                return;
            }

            this.disconnect();

            if (error.code === 514) {
                this._showError("Connection error", "Server timeout.");
            } else if (error.code === 515) {
                this._showSuccess("Session complete", "Backing VM has disconnected.");
            } else if (error.code === 522) {
                this._showWarning("Session ended", "Session timed out due to inactivity.");
            } else {
                const _msg = `An unexpected error occurred: ${error.message}`;
                this._showError("Connection error", _msg);
            }
        };

        this.tunnel.onerror = handler;
        this.client.onerror = handler;
    }

    connect() {
        if (this.connected) {
            this.client.disconnect();
            this.connected = false;
        }

        try {
            this.client.connect($.param({
                'recording_name': this.config.recording_name,
            }));
            this.connected = true;
        } catch (e) {
            console.warn(e);
            this.connected = false;
            throw e;
        }
    }

    disconnect() {
        if (this.connected) {
            this.client.disconnect();
            this.connected = false;
        }
    }
}

function GuacMe(element, session_id, recording_name) {
    return new GuacSession(element, { session_id, recording_name });
}

function getCsrfToken() {
    var match = document.cookie.match(/csrftoken=([^;]+)/);
    return match ? match[1] : '';
}

function stopTask(taskId, onSuccess, onError) {
    var btn = document.getElementById('stopTask');
    if (btn) { btn.disabled = true; btn.innerHTML = '<i class="fas fa-spinner fa-spin me-1"></i>Stopping...'; }
  
    const apiUrl = location.origin + "/apiv2/tasks/status/" + taskId + "/";

    fetch(apiUrl, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'X-CSRFToken': getCsrfToken(),
        },
        body: JSON.stringify({ status: 'finish' }),
    })
    .then(response => response.json())
    .then(data => {
        console.log('Response:', data);
        if (onSuccess) onSuccess(data);
        location.replace(location.origin + '/submit/status/' + taskId + '/');
    })
    .catch(error => {
        console.error('Error:', error);
        if (onError) onError(error);
        if (btn) { btn.disabled = false; btn.innerHTML = '<i class="fas fa-stop-circle me-1"></i>End Session'; }
    });
}
