function GuacMe(element, session_id, recording_name) {
    "use strict";

    var terminal_connected = false;
    var terminal_client;
    var terminal_element;
    var dialog_container;

    var init = function() {
        dialog_container = $(element).find('.guaconsole')[0];

        var terminal_ws_url = location.origin.replace(/^http(s?):/, function(match, p1) {
            return (p1 ? 'wss:' : 'ws:');
        });

        terminal_client = new Guacamole.Client(
            new Guacamole.WebSocketTunnel(terminal_ws_url + '/guac/websocket-tunnel/' + session_id)
        );
        terminal_connect(recording_name);

        terminal_element = terminal_client.getDisplay().getElement();
        $('#terminal').append(terminal_element);

        /* Scale display to fit the browser window. */
        var scaleDisplay = function() {
            var display = terminal_client.getDisplay();
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

        /* Re-scale when the display size changes (initial connect). */
        terminal_client.getDisplay().onresize = function() {
            scaleDisplay();
        };

        /* Re-scale on browser window resize (debounced). */
        var resizeTimeout;
        window.addEventListener('resize', function() {
            clearTimeout(resizeTimeout);
            resizeTimeout = setTimeout(scaleDisplay, 100);
        });

        /* Disconnect on tab close. */
        window.onunload = function() {
            terminal_client.disconnect();
        };

        /* Mouse handling */
        var mouse = new Guacamole.Mouse(terminal_element);

        mouse.onmousedown =
        mouse.onmouseup   =
        mouse.onmousemove = function(mouseState) {
            terminal_client.sendMouseState(mouseState, true);
        };

        var keyboard = new Guacamole.Keyboard(terminal_element);
        var ctrl, shift = false;

        keyboard.onkeydown = function (keysym) {
            var cancel_event = true;

            if (keysym == 0xFFE1 || keysym == 0xFFE3 || keysym == 0xFF63
                || keysym == 0x0056 || keysym == 0x0076) {
                cancel_event = false;
            }

            if (keysym == 0xFFE1) { shift = true; }
            else if (keysym == 0xFFE3) { ctrl = true; }

            if ((ctrl && shift && keysym == 0x0056)
                || (ctrl && keysym == 0x0076)
                || (shift && keysym == 0xFF63)) {
                window.setTimeout(function() {
                    terminal_client.sendKeyEvent(1, keysym);
                }, 50);
            } else {
                terminal_client.sendKeyEvent(1, keysym);
            }

            return !cancel_event;
        };

        keyboard.onkeyup = function (keysym) {
            if (keysym == 0xFFE1) { shift = false; }
            else if (keysym == 0xFFE3) { ctrl = false; }

            if ((ctrl && shift && keysym == 0x0056)
                || (ctrl && keysym == 0x0076)
                || (shift && keysym == 0xFF63)) {
                window.setTimeout(function() {
                    terminal_client.sendKeyEvent(0, keysym);
                }, 50);
            } else {
                terminal_client.sendKeyEvent(0, keysym);
            }
        };

        $(terminal_element)
            .attr('tabindex', 1)
            .hover(
                function() {
                    var x = window.scrollX, y = window.scrollY;
                    $(this).focus();
                    window.scrollTo(x, y);
                },
                function() { $(this).blur(); }
            )
            .blur(function() { keyboard.reset(); });

        $(document).on('paste', function(e) {
            var text = e.originalEvent.clipboardData.getData('text/plain');
            if ($(terminal_element).is(":focus")) {
                terminal_client.setClipboard(text);
            }
        });

        terminal_client.onerror = function(guac_error) {
            terminal_client.disconnect();

            var dialog = $('#launch_error');
            var dialog_message =
                "Could not connect to guest vm. " +
                "The client detected an unexpected error. " +
                "The server's error message was:";
            var error_message = guac_error.message;

            if (guac_error.message.toLowerCase().startsWith('aborted')) {
                dialog_message = "Remote session terminated.";
                error_message = "Close tab.";
            }
            dialog.find('.message').html(dialog_message);
            dialog.find('.error_msg').html(error_message);
            dialog.dialog({dialogClass: 'no-close'});
            dialog.dialog(dialog_container);
        };
    };

    var terminal_connect = function(recording_name) {
        if (terminal_connected) {
            terminal_client.disconnect();
            terminal_connected = false;
        }

        try {
            terminal_client.connect($.param({
                'recording_name': recording_name,
            }));
            terminal_connected = true;
        } catch (e) {
            console.warn(e);
            terminal_connected = false;
            throw e;
        }
    };

    init();
}

function stopTask(taskId) {
    var apiUrl = location.origin + "/apiv2/tasks/status/" + taskId + "/";

    fetch(apiUrl, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ status: 'finish' }),
    })
    .then(response => response.json())
    .then(data => console.log('Response:', data))
    .catch(error => console.error('Error:', error));
}
