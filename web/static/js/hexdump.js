/**
 * hexy js - https://github.com/a2800276/hexy.js
 *  modified for cuckoo/web
 * Updated with changes from https://gist.github.com/username1565/18878422a72ef0e7f05edf72536b6ed9
 */

var base64 = {
    _keyStr: "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=",

    decode: function(input) {
        var output = [];
        var chr1, chr2, chr3;
        var enc1, enc2, enc3, enc4;
        var i = 0;

        input = input.replace(/[^A-Za-z0-9\+\/\=]/g, "");

        while (i < input.length) {
            enc1 = this._keyStr.indexOf(input.charAt(i++));
            enc2 = this._keyStr.indexOf(input.charAt(i++));
            enc3 = this._keyStr.indexOf(input.charAt(i++));
            enc4 = this._keyStr.indexOf(input.charAt(i++));

            chr1 = (enc1 << 2) | (enc2 >> 4);
            chr2 = ((enc2 & 15) << 4) | (enc3 >> 2);
            chr3 = ((enc3 & 3) << 6) | enc4;

            output.push(chr1);

            if (enc3 != 64) {
                output.push(chr2);
            }
            if (enc4 != 64) {
                output.push(chr3);
            }
        }
        return output; // Retorna array de bytes
    }
};

var hexy = function (buffer, config) {
    var h = new Hexy(buffer, config);
    return h.toString();
};

var Hexy = function (buffer, config) {
    var self = this;
    config = config || {};

    // --- Lógica de unificación de tipos (traída de hexdump2.js) ---
    // Normalizamos cualquier entrada a un Array o String binario para procesarlo
    if (buffer instanceof ArrayBuffer) {
        buffer = new Uint8Array(buffer);
    }
    // Si es Uint8Array, lo convertimos a array normal para facilitar manejo
    if (buffer.constructor === Uint8Array) {
        buffer = Array.from(buffer);
    }
    // --------------------------------------------------------------

    self.buffer = buffer;
    self.width = config.width || 16;
    self.numbering = config.numbering == "none" ? "none" : "hex_bytes";
    self.format = (config.format === "none" || config.format === "twos") ? config.format : "fours";
    self.caps = config.caps == "upper" ? "upper" : "lower";
    self.annotate = config.annotate == "none" ? "none" : "ascii";
    self.prefix = config.prefix || "";
    self.indent = config.indent || 0;
    self.html = config.html || false;
    self.should_escape = config.escape !== false;
    self.offset = config.offset || 0;
    self.length = config.length || -1;
    self.display_offset = config.display_offset || 0;

    // Manejo de slice y offset
    if (self.offset) {
        if (self.offset < self.buffer.length) {
            self.buffer = self.buffer.slice(self.offset);
        }
    }
    if (self.length !== -1) {
        if (self.length <= self.buffer.length) {
            self.buffer = self.buffer.slice(0, self.length);
        }
    }

    // Indentación
    for (var i = 0; i != self.indent; ++i) {
        self.prefix = " " + self.prefix;
    }

    this.toString = function () {
        var str = "";
        if (self.html) { str += "<div class='hexy'>\n"; }

        var line_arr = lines();

        for (var i = 0; i != line_arr.length; ++i) {
            var hex_raw = line_arr[i],
                hex = hex_raw[0],
                raw = hex_raw[1];

            // Formatear grupos (fours o twos)
            var howMany = hex.length;
            if (self.format === "fours") { howMany = 4; }
            else if (self.format === "twos") { howMany = 2; }

            var hex_formatted = "";
            for (var j = 0; j < hex.length; j += howMany) {
                var s = hex.substr(j, howMany);
                hex_formatted += s + " ";
            }

            var addr = (i * self.width) + self.offset + self.display_offset;

            if (self.html) {
                var odd = i % 2 == 0 ? " even" : "  odd";
                str += "<div class='" + pad(addr, 8) + odd + "'>";
            }

            str += self.prefix;

            if (self.numbering === "hex_bytes") {
                str += pad(addr, 8);
                str += ": ";
            }

            var padlen = 0;
            switch (self.format) {
                case "fours": padlen = self.width * 2 + self.width / 2; break;
                case "twos": padlen = self.width * 3 + 2; break;
                default: padlen = self.width * 2 + 1;
            }

            str += rpad(hex_formatted, padlen);

            if (self.annotate === "ascii") {
                str += " ";
                // Limpieza de caracteres no imprimibles para ASCII
                var ascii = raw.replace(/[\000-\040\177-\377]/g, ".");
                str += self.should_escape ? escape(ascii) : ascii;
            }

            if (self.html) { str += "</div>\n"; }
            else { str += "\n"; }
        }

        if (self.html) { str += "</div>\n"; }
        return str;
    };

    var lines = function () {
        var hex_raw = [];
        for (var i = 0; i < self.buffer.length; i += self.width) {
            var begin = i;
            var end = i + self.width >= self.buffer.length ? self.buffer.length : i + self.width;
            var slice = self.buffer.slice(begin, end);

            var hex = self.caps === "upper" ? hexu(slice) : hexl(slice);

            // Convertir slice a string para la columna raw/ascii
            var raw = "";
            for(var k=0; k < slice.length; k++) {
                // Maneja tanto string como array de bytes
                var charCode = (typeof slice === 'string') ? slice.charCodeAt(k) : slice[k];
                raw += String.fromCharCode(charCode);
            }

            hex_raw.push([hex, raw]);
        }
        return hex_raw;
    };

    var hexl = function (buffer) {
        var str = "";
        for (var i = 0; i != buffer.length; ++i) {
            var byte = (typeof buffer === 'string') ? buffer.charCodeAt(i) : buffer[i];
            str += pad(byte, 2);
        }
        return str;
    };

    var hexu = function (buffer) {
        return hexl(buffer).toUpperCase();
    };

    var pad = function (b, len) {
        var s = b.toString(16);
        while (s.length < len) { s = "0" + s; }
        return s;
    };

    var rpad = function (s, len) {
        for (var n = len - s.length; n > 0; --n) {
            if (self.html) { s += "&nbsp;"; }
            else { s += " "; }
        }
        return s;
    };

    var escape = function (str) {
        return str.replace(/&/g, "&amp;")
                  .replace(/</g, "&lt;")
                  .replace(/>/g, "&gt;");
    };
};

/**
 * Función Helper solicitada
 * @param {string} str - Cadena en Base64
 * @param {string|number} mode - Ancho (ej. 16)
 * @param {boolean} should_escape - Si se debe escapar HTML (default true)
 */
function renderHex(str, mode, should_escape) {
    if (!str) return "";
    // Decodifica base64 a array de bytes y pasa a hexy
    return hexy(base64.decode(str), {
        width: mode ? parseInt(mode) : 16,
        html: false, // Cambiar a true si necesitas HTML
        escape: should_escape !== undefined ? should_escape : true
    });
}
