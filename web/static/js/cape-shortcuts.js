/**
 * CAPEv2 Global Keyboard Shortcuts
 * Enhances analyst workflow by providing keyboard navigation.
 */

(function() {
    'use strict';

    document.addEventListener('keydown', function(e) {
        // Don't trigger if user is typing in an input or textarea
        const activeElement = document.activeElement;
        const isInput = activeElement && (
                        activeElement.tagName === 'INPUT' || 
                        activeElement.tagName === 'TEXTAREA' || 
                        activeElement.tagName === 'SELECT' || 
                        activeElement.isContentEditable);

        if (isInput && e.key !== 'Escape') {
            return;
        }

        // Global Key handlers
        switch(e.key) {
            case '/':
                e.preventDefault();
                const globalSearch = document.getElementById('form_search');
                if (globalSearch) {
                    globalSearch.focus();
                    globalSearch.select();
                }
                break;

            case 'Escape':
                if (isInput) {
                    activeElement.blur();
                }
                // Close any open modals
                $('.modal.show').modal('hide');
                break;

            case '1': case '2': case '3': case '4': case '5': case '6': case '7': case '8': case '9':
                if (e.altKey) {
                    e.preventDefault();
                    const tabIndex = parseInt(e.key) - 1;
                    const tabs = $('#reportTabs .nav-link, #analysisTabs .nav-link');
                    if (tabs[tabIndex]) {
                        tabs[tabIndex].click();
                    }
                }
                break;

            case 'j': // Next Item
                navigateList(1);
                break;
            
            case 'k': // Previous Item
                navigateList(-1);
                break;

            case 'o': // Open/Expand
                const activeRow = $('.table-hover tbody tr.keyboard-active');
                if (activeRow.length) {
                    const link = activeRow.find('a').first();
                    if (link.length) link[0].click();
                }
                break;

            case '?': // Show help
                const helpModal = bootstrap.Modal.getOrCreateInstance(document.getElementById('shortcutsHelpModal'));
                helpModal.show();
                break;
        }
    });

    /**
     * Helper to navigate tables/lists via J/K
     */
    function navigateList(direction) {
        const rows = $('.table-hover tbody tr:visible, #diff-table tbody tr:visible');
        if (!rows.length) return;

        let currentIndex = rows.index($('.keyboard-active'));
        let nextIndex = currentIndex + direction;

        if (currentIndex === -1 && direction === 1) nextIndex = 0;
        if (nextIndex < 0) nextIndex = 0;
        if (nextIndex >= rows.length) nextIndex = rows.length - 1;

        rows.removeClass('keyboard-active');
        const nextRow = $(rows[nextIndex]);
        nextRow.addClass('keyboard-active');

        // Scroll into view if needed
        const rowTop = nextRow.offset().top;
        const rowBottom = rowTop + nextRow.height();
        const winTop = $(window).scrollTop() + 100; // Header offset
        const winBottom = $(window).scrollTop() + $(window).height();

        if (rowTop < winTop || rowBottom > winBottom) {
            $('html, body').animate({
                scrollTop: rowTop - 150
            }, 50);
        }
    }

    // Add visual feedback for keyboard navigation
    const style = document.createElement('style');
    style.innerHTML = `
        .keyboard-active { 
            outline: 2px solid #3498db !important; 
            outline-offset: -2px;
            background-color: rgba(52, 152, 219, 0.1) !important;
        }
    `;
    document.head.appendChild(style);

})();
