/**
 * CAPEv2 Omni-Box (Spotlight Search)
 * Central command palette for quick access and searching.
 */

window.CapeOmniBox = (function() {
    'use strict';

    const menuTemplate = `
        <div id="cape-omnibox" 
             x-data="capeOmniBox" 
             x-show="open" 
             @keydown.window.prevent.ctrl.k="open = true; $nextTick(() => $refs.searchInput.focus())"
             @keydown.window.prevent.cmd.k="open = true; $nextTick(() => $refs.searchInput.focus())"
             @keydown.escape.window="open = false"
             style="display: none;"
             class="omnibox-overlay"
             x-cloak>
            
            <div class="omnibox-content bg-dark border border-secondary shadow-lg rounded" @click.away="open = false">
                <div class="p-3 border-bottom border-secondary d-flex align-items-center">
                    <i class="fas fa-search me-3 text-primary"></i>
                    <input type="text" 
                           x-ref="searchInput"
                           x-model="query" 
                           @input.debounce.300ms="search"
                           @keydown.arrow-down.prevent="selectNext"
                           @keydown.arrow-up.prevent="selectPrev"
                           @keydown.enter.prevent="executeActive"
                           class="form-control form-control-lg bg-transparent border-0 text-white shadow-none" 
                           placeholder="Search analyses, IPs, hashes... (Prefixes: ip:, hash:, domain:, id:)" />
                </div>

                <div class="omnibox-results custom-scrollbar" style="max-height: 400px; overflow-y: auto;">
                    <template x-if="results.length > 0">
                        <div class="p-2">
                            <template x-for="(result, index) in results" :key="index">
                                <div :class="{'bg-primary text-white': activeIndex === index, 'text-light': activeIndex !== index}"
                                     class="p-2 rounded cursor-pointer d-flex justify-content-between align-items-center mb-1"
                                     @mouseenter="activeIndex = index"
                                     @click="goToResult(result)">
                                    <div class="d-flex align-items-center">
                                        <i class="fas me-3 opacity-50" :class="getIcon(result.type)"></i>
                                        <div>
                                            <div class="fw-bold small" x-text="result.title"></div>
                                            <div class="x-small opacity-75" x-text="result.subtitle"></div>
                                        </div>
                                    </div>
                                    <div class="x-small opacity-50 font-monospace" x-text="result.meta"></div>
                                </div>
                            </template>
                        </div>
                    </template>
                    <template x-if="results.length === 0 && query.length > 0 && !loading">
                        <div class="p-5 text-center text-white-50">
                            <i class="fas fa-search-minus fa-2x mb-3"></i>
                            <p>No results found for "<span x-text="query"></span>"</p>
                        </div>
                    </template>
                    <template x-if="loading">
                        <div class="p-4 text-center">
                            <i class="fas fa-spinner fa-spin fa-2x text-primary"></i>
                        </div>
                    </template>
                    <template x-if="query.length === 0">
                        <div class="p-4">
                            <h6 class="text-white-50 small text-uppercase mb-3 px-2">Quick Commands</h6>
                            <div class="row g-2">
                                <div class="col-4">
                                    <a href="/submission" class="btn btn-dark w-100 text-start border-secondary small py-2"><i class="fas fa-upload me-2 text-primary"></i>Submit</a>
                                </div>
                                <div class="col-4">
                                    <a href="/analysis" class="btn btn-dark w-100 text-start border-secondary small py-2"><i class="fas fa-list me-2 text-info"></i>Recent</a>
                                </div>
                                <div class="col-4">
                                    <a href="/dashboard" class="btn btn-dark w-100 text-start border-secondary small py-2"><i class="fas fa-tachometer-alt me-2 text-warning"></i>Dashboard</a>
                                </div>
                            </div>
                        </div>
                    </template>
                </div>
                
                <div class="p-2 border-top border-secondary bg-dark bg-opacity-50 rounded-bottom d-flex justify-content-between align-items-center">
                    <div class="text-white-50 x-small">
                        <kbd class="bg-secondary">↑↓</kbd> navigate &bull; <kbd class="bg-secondary">↵</kbd> select &bull; <kbd class="bg-secondary">esc</kbd> close
                    </div>
                    <div class="text-primary x-small fw-bold">CAPE Omni-Box</div>
                </div>
            </div>
        </div>
    `;

    function init() {
        const container = document.createElement('div');
        container.innerHTML = menuTemplate;
        document.body.appendChild(container);

        document.addEventListener('alpine:init', () => {
            Alpine.data('capeOmniBox', () => ({
                open: false,
                query: '',
                results: [],
                loading: false,
                activeIndex: 0,

                search() {
                    if (this.query.length < 2) {
                        this.results = [];
                        return;
                    }

                    this.loading = true;
                    
                    // Parse query for prefixes
                    let option = 'name'; // Default
                    let argument = this.query;

                    const prefixes = {
                        'ip:': 'ip',
                        'hash:': 'target_sha256',
                        'domain:': 'domain',
                        'id:': 'id',
                        'ttp:': 'ttp'
                    };

                    for (const [prefix, opt] of Object.entries(prefixes)) {
                        if (this.query.startsWith(prefix)) {
                            option = opt;
                            argument = this.query.substring(prefix.length).trim();
                            break;
                        }
                    }

                    fetch('/apiv2/tasks/extendedsearch/', {
                        method: 'POST',
                        headers: { 
                            'Content-Type': 'application/json',
                            'X-CSRFToken': getCookie('csrftoken')
                        },
                        body: JSON.stringify({ option, argument, lean: true, search_limit: 10 })
                    })
                    .then(r => r.json())
                    .then(data => {
                        this.results = (data || []).map(item => ({
                            type: 'analysis',
                            title: item.analysis?.id ? `Analysis #${item.analysis.id}` : 'Unknown Task',
                            subtitle: item.target?.file?.name || item.target?.url || 'N/A',
                            meta: item.info?.package || '',
                            id: item.analysis?.id,
                            raw: item
                        }));
                        this.activeIndex = 0;
                    })
                    .finally(() => this.loading = false);
                },

                getIcon(type) {
                    return {
                        'analysis': 'fa-microscope',
                        'command': 'fa-terminal'
                    }[type] || 'fa-dot-circle';
                },

                selectNext() {
                    if (this.activeIndex < this.results.length - 1) this.activeIndex++;
                },

                selectPrev() {
                    if (this.activeIndex > 0) this.activeIndex--;
                },

                executeActive() {
                    if (this.results[this.activeIndex]) {
                        this.goToResult(this.results[this.activeIndex]);
                    }
                },

                goToResult(result) {
                    if (result.id) {
                        window.location.href = `/analysis/${result.id}/`;
                    }
                }
            }));
        });
    }

    function getCookie(name) {
        let cookieValue = null;
        if (document.cookie && document.cookie !== '') {
            const cookies = document.cookie.split(';');
            for (let i = 0; i < cookies.length; i++) {
                const cookie = cookies[i].trim();
                if (cookie.substring(0, name.length + 1) === (name + '=')) {
                    cookieValue = decodeURIComponent(cookie.substring(name.length + 1));
                    break;
                }
            }
        }
        return cookieValue;
    }

    return { init };
})();

CapeOmniBox.init();
