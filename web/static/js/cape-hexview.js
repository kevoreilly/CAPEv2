/**
 * CAPEv2 Advanced Hex Viewer
 * Provides a modern, interactive hex/ASCII view for binary data.
 */

window.CapeHexView = (function() {
    'use strict';

    function render(containerId, data, options = {}) {
        const container = document.getElementById(containerId);
        if (!container) return;

        const config = {
            bytesPerLine: options.bytesPerLine || 16,
            baseOffset: options.baseOffset || 0,
            highlightOffset: options.highlightOffset || null,
            ...options
        };

        let bytes;
        if (typeof data === 'string') {
            // Assume base64 if it looks like it, otherwise raw string
            try {
                const binary = atob(data);
                bytes = new Uint8Array(binary.length);
                for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
            } catch(e) {
                bytes = new TextEncoder().encode(data);
            }
        } else {
            bytes = new Uint8Array(data);
        }

        const lines = [];
        for (let i = 0; i < bytes.length; i += config.bytesPerLine) {
            const chunk = bytes.slice(i, i + config.bytesPerLine);
            lines.push(renderLine(i, chunk, config));
        }

        container.innerHTML = `
            <div class="cape-hexview-container">
                <div class="cape-hexview-header">
                    <div class="offset-header">Offset</div>
                    <div class="hex-header">Hex</div>
                    <div class="ascii-header">ASCII</div>
                </div>
                <div class="cape-hexview-body">
                    ${lines.join('')}
                </div>
            </div>
        `;

        setupInteractions(container);
    }

    function renderLine(offset, chunk, config) {
        const hexParts = [];
        const asciiParts = [];
        
        const displayOffset = (config.baseOffset + offset).toString(16).padStart(8, '0').toUpperCase();

        for (let i = 0; i < config.bytesPerLine; i++) {
            if (i < chunk.length) {
                const b = chunk[i];
                const hex = b.toString(16).padStart(2, '0').toUpperCase();
                const char = (b >= 32 && b <= 126) ? String.fromCharCode(b) : '.';
                
                const isMatch = config.highlightOffset !== null && (offset + i) === config.highlightOffset;
                const highlightClass = isMatch ? 'highlighted' : '';

                hexParts.push(`<span class="hex-byte ${highlightClass}" data-offset="${offset + i}">${hex}</span>`);
                asciiParts.push(`<span class="ascii-byte ${highlightClass}" data-offset="${offset + i}">${escapeHtml(char)}</span>`);
            } else {
                hexParts.push('<span class="hex-byte empty">  </span>');
                asciiParts.push('<span class="ascii-byte empty"> </span>');
            }
            
            if ((i + 1) % 8 === 0 && i < config.bytesPerLine - 1) {
                hexParts.push('<span class="spacer"> </span>');
            }
        }

        return `
            <div class="hex-line">
                <span class="offset">${displayOffset}</span>
                <span class="hex-col">${hexParts.join(' ')}</span>
                <span class="ascii-col">${asciiParts.join('')}</span>
            </div>
        `;
    }

    function setupInteractions(container) {
        $(container).on('mouseenter', '.hex-byte, .ascii-byte', function() {
            const offset = $(this).data('offset');
            $(container).find(`[data-offset="${offset}"]`).addClass('hover');
        }).on('mouseleave', '.hex-byte, .ascii-byte', function() {
            const offset = $(this).data('offset');
            $(container).find(`[data-offset="${offset}"]`).removeClass('hover');
        });
    }

    function escapeHtml(unsafe) {
        return unsafe
             .replace(/&/g, "&amp;")
             .replace(/</g, "&lt;")
             .replace(/>/g, "&gt;")
             .replace(/"/g, "&quot;")
             .replace(/'/g, "&#039;");
    }

    return { render };
})();
