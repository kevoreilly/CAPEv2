/**
 * CAPEv2 Contextual Pivot Menus
 * Allows analysts to pivot from any data point to internal searches or external tools.
 */

window.CapePivot = (function() {
    'use strict';

    const menuTemplate = `
        <div id="cape-pivot-menu" 
             x-data="capePivotMenu" 
             x-show="open" 
             @click.away="open = false" 
             @contextmenu.prevent
             class="dropdown-menu show shadow-lg border-secondary bg-dark text-white p-2"
             style="position: fixed; z-index: 9999; min-width: 200px;"
             :style="\`left: \${x}px; top: \${y}px;\`"
             x-transition>
            
            <div class="px-3 py-1 mb-2 border-bottom border-secondary">
                <small class="text-white-50 text-uppercase fw-bold" x-text="type"></small>
                <div class="text-truncate font-monospace small" :title="value" x-text="value"></div>
            </div>

            <!-- Internal Pivots -->
            <h6 class="dropdown-header text-info px-2 small mt-1">Internal Pivot</h6>
            <a class="dropdown-item py-1 rounded small" :href="\`/analysis/search/\${type}:\${value}/\`"><i class="fas fa-search me-2"></i>Find all tasks</a>
            <template x-if="type === 'ip' || type === 'domain'">
                <button class="dropdown-item py-1 rounded small" @click="filterReport"><i class="fas fa-filter me-2"></i>Filter this report</button>
            </template>

            <!-- External Tools -->
            <h6 class="dropdown-header text-warning px-2 small mt-2">Threat Intel</h6>
            <template x-if="type === 'hash' || type === 'sha256' || type === 'md5'">
                <a class="dropdown-item py-1 rounded small" :href="\`https://www.virustotal.com/gui/file/\${value}\`" target="_blank"><i class="fas fa-shield-virus me-2"></i>VirusTotal</a>
            </template>
            <template x-if="type === 'ip'">
                <a class="dropdown-item py-1 rounded small" :href="\`https://www.virustotal.com/gui/ip-address/\${value}\`" target="_blank"><i class="fas fa-shield-virus me-2"></i>VirusTotal</a>
                <a class="dropdown-item py-1 rounded small" :href="\`https://www.shodan.io/host/\${value}\`" target="_blank"><i class="fas fa-globe me-2"></i>Shodan</a>
                <a class="dropdown-item py-1 rounded small" :href="\`https://abuseipdb.com/check/\${value}\`" target="_blank"><i class="fas fa-user-shield me-2"></i>AbuseIPDB</a>
            </template>
            <template x-if="type === 'domain'">
                <a class="dropdown-item py-1 rounded small" :href="\`https://www.virustotal.com/gui/domain/\${value}\`" target="_blank"><i class="fas fa-shield-virus me-2"></i>VirusTotal</a>
                <a class="dropdown-item py-1 rounded small" :href="\`https://urlscan.io/search/#\${value}\`" target="_blank"><i class="fas fa-search me-2"></i>urlscan.io</a>
            </template>

            <!-- Actions -->
            <h6 class="dropdown-header text-secondary px-2 small mt-2">Actions</h6>
            <button class="dropdown-item py-1 rounded small" @click="copyToClipboard"><i class="fas fa-copy me-2"></i>Copy value</button>
        </div>
    \`;

    function init() {
        if (!document.body) {
            document.addEventListener('DOMContentLoaded', init);
            return;
        }

        // Inject menu container into body
        const container = document.createElement('div');
        container.innerHTML = menuTemplate;
        document.body.appendChild(container);

        // Register Alpine component
        document.addEventListener('alpine:init', () => {
            Alpine.data('capePivotMenu', () => ({
                open: false,
                x: 0,
                y: 0,
                type: '',
                value: '',

                toggle(event, type, value) {
                    this.open = true;
                    this.type = type;
                    this.value = value;
                    this.x = event.clientX;
                    this.y = event.clientY;

                    // Ensure menu doesn't go off-screen
                    this.$nextTick(() => {
                        const menu = document.getElementById('cape-pivot-menu');
                        if (this.x + menu.offsetWidth > window.innerWidth) {
                            this.x -= menu.offsetWidth;
                        }
                        if (this.y + menu.offsetHeight > window.innerHeight) {
                            this.y -= menu.offsetHeight;
                        }
                    });
                },

                copyToClipboard() {
                    navigator.clipboard.writeText(this.value);
                    this.open = false;
                },

                filterReport() {
                    // Logic to find the current active DataTable and search it
                    const activeTable = $('.tab-pane.active .dataTable').first();
                    if (activeTable.length) {
                        activeTable.DataTable().search(this.value).draw();
                    }
                    this.open = false;
                }
            }));
        });

        // Global Event Listener for data-pivot elements
        document.addEventListener('contextmenu', (e) => {
            const pivotEl = e.target.closest('[data-pivot]');
            if (pivotEl) {
                e.preventDefault();
                const type = pivotEl.getAttribute('data-pivot');
                const value = pivotEl.innerText.trim().split(' ')[0]; // Handle cases with badges/text following
                
                // Get the Alpine component instance and toggle it
                const menu = document.getElementById('cape-pivot-menu').__x.$data;
                menu.toggle(e, type, value);
            }
        });
        
        // Also support left-click with a special class if desired, but context menu is cleaner
    }

    return { init };
})();

CapePivot.init();
