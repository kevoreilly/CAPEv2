function GuacMe(element, guest_ip, vncport, session_id, recording_name) {
    "use strict";

    var terminal_connected = false;
    var terminal_client;
    var terminal_element;
    var dialog_container;

    var init = function() {
        /* Process terminal URL. */

        dialog_container = $(element).find('.guaconsole')[0];
        
        /* Build websocket url based on protocol */
        var terminal_ws_url = location.origin.replace(/^http(s?):/, function(match, p1) {
            return (p1 ? 'wss:' : 'ws:');
        });

        /* Initialize Guacamole Client */
        terminal_client = new Guacamole.Client(
            new Guacamole.WebSocketTunnel(terminal_ws_url + '/guac/websocket-tunnel/' + session_id)
        );
        terminal_connect(guest_ip, vncport, recording_name);

        terminal_element = terminal_client.getDisplay().getElement();

        /* Show the terminal.  */
        $('#terminal').append(terminal_element);

        /* Disconnect on tab close. */
        window.onunload = function() {
            terminal_client.disconnect();
        };

        /* Mouse handling */
        var mouse = new Guacamole.Mouse(terminal_element);

        mouse.onmousedown =
        mouse.onmouseup   =
        mouse.onmousemove = function(mouseState) {
            terminal_client.sendMouseState(mouseState);
        };

        /* Keyboard handling.  */
        var keyboard = new Guacamole.Keyboard(terminal_element);
        var ctrl, shift = false;

        keyboard.onkeydown = function (keysym) {
            var cancel_event = true;

            /* Don't cancel event on paste shortcuts. */
            if (keysym == 0xFFE1 /* shift */
                || keysym == 0xFFE3 /* ctrl */
                || keysym == 0xFF63 /* insert */
                || keysym == 0x0056 /* V */
                || keysym == 0x0076 /* v */
            ) {
                cancel_event = false;
            }

            /* Remember when ctrl or shift are down. */
            if (keysym == 0xFFE1) {
                shift = true;
            } else if (keysym == 0xFFE3) {
                ctrl = true;
            }

            /* Delay sending final stroke until clipboard is updated. */
            if ((ctrl && shift && keysym == 0x0056) /* ctrl-shift-V */
                || (ctrl && keysym == 0x0076) /* ctrl-v */
                || (shift && keysym == 0xFF63) /* shift-insert */
            ) {
                window.setTimeout(function() {
                    terminal_client.sendKeyEvent(1, keysym);
                }, 50);
            } else {
                terminal_client.sendKeyEvent(1, keysym);
            }

            return !cancel_event;
        };

        keyboard.onkeyup = function (keysym) {
            /* Remember when ctrl or shift are released. */
            if (keysym == 0xFFE1) {
                shift = false;
            } else if (keysym == 0xFFE3) {
                ctrl = false;
            }

            /* Delay sending final stroke until clipboard is updated. */
            if ((ctrl && shift && keysym == 0x0056) /* ctrl-shift-v */
                || (ctrl && keysym == 0x0076) /* ctrl-v */
                || (shift && keysym == 0xFF63) /* shift-insert */
            ) {
                window.setTimeout(function() {
                    terminal_client.sendKeyEvent(0, keysym);
                }, 50);
            } else {
                terminal_client.sendKeyEvent(0, keysym);
            }
        };

        $(terminal_element)
            /* Set tabindex so that element can be focused.  Otherwise, no
            * keyboard events will be registered for it. */
            .attr('tabindex', 1)
            /* Focus on the element based on mouse movement.  Simply
            * letting the user click on it doesn't work. */
            .hover(
                function() {
                var x = window.scrollX, y = window.scrollY;
                $(this).focus();
                window.scrollTo(x, y);
                }, function() {
                $(this).blur();
                }
            )
            /* Release all keys when the element loses focus. */
            .blur(function() {
                keyboard.reset();
            });

        /* Handle paste events when the element is in focus. */
        $(document).on('paste', function(e) {
            var text = e.originalEvent.clipboardData.getData('text/plain');
            if ($(terminal_element).is(":focus")) {
                terminal_client.setClipboard(text);
            }
        });

        /* Error handling. */
        terminal_client.onerror = function(guac_error) {
            /* Reset and disconnect. */
            terminal_client.disconnect();

            var dialog = $('#launch_error');
            var dialog_message =
                "Could not connect to guest vm. " +
                "The client detected an unexpected error. " +
                "The server's error message was:";
            var error_message = guac_error.message;

            if (guac_error.message.toLowerCase().startsWith('aborted')) {
                dialog_message = "Remote session terminated."
                error_message = "Close tab.";
            }
            dialog.find('.message').html(dialog_message);
            dialog.find('.error_msg').html(error_message);
            dialog.dialog({dialogClass: 'no-close'});
            dialog.dialog(dialog_container);
        };


    };

    var terminal_connect = function(guest_ip, vncport, recording_name) {
        if (terminal_connected) {
            terminal_client.disconnect()
            terminal_connected = false;
        }

        try {
            terminal_client.connect($.param({
                'guest_ip': guest_ip,
                'vncport': vncport,
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

    var postData = {
        status: 'finish',
    };

    fetch(apiUrl, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify(postData),
    })
    .then(response => response.json())
    .then(data => {
        console.log('Response:', data);
    })
    .catch(error => {
        console.error('Error:', error);
    });
}