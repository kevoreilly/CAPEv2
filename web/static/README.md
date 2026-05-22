# Static Assets Documentation

This directory contains locally hosted JavaScript and CSS libraries used by the CAPEv2 WebGUI.

## Modernization Libraries (PoC)

To maintain stability and support air-gapped environments, the following libraries have been internalized:

| Library | Version | File(s) | Description |
| :--- | :--- | :--- | :--- |
| **HTMX** | 2.0.1 | `js/htmx.min.js` | Declarative AJAX and partial page updates. |
| **Response-Targets** | 2.0.0 | `js/response-targets.js` | HTMX extension for targeting specific elements on error responses. |
| **DataTables** | 2.1.2 | `js/jquery.dataTables.min.js`, `js/dataTables.bootstrap5.min.js`, `css/dataTables.bootstrap5.min.css` | Advanced searchable and sortable data grids. |
| **D3.js** | 7.9.0 | `js/d3.v7.min.js` | Interactive data visualizations (e.g., Process Tree). |
| **ApexCharts** | 3.51.0 | `js/apexcharts.min.js` | Interactive charting for resource monitoring. |
| **Alpine.js** | 3.14.1 | `js/alpine.min.js` | Lightweight UI state management. |
| **CapeHexView** | 1.0.0 | `js/cape-hexview.js`, `css/cape-hexview.css` | Custom advanced binary/hex viewer. |
| **CapeShortcuts**| 1.0.0 | `js/cape-shortcuts.js` | Global keyboard-driven workflow. |

## Core Libraries

| Library | Version | File(s) |
| :--- | :--- | :--- |
| **jQuery** | 3.7.1 | `js/jquery.js` |
| **Bootstrap** | 5.3.3 | `css/bootstrap.min.css`, `js/bootstrap.bundle.min.js` |
| **FontAwesome** | 5.15.4 | `css/fontawesome-all.css` |
| **Moment.js** | 2.30.1 | `js/moment.min.js` |
| **Lightbox** | 2.11.4 | `css/lightbox.css`, `js/lightbox.js` |

## Legacy / Specialized

*   **Guacamole Client:** v1.6.0 (`js/guacamole-1.6.0-all.min.js`)
*   **Pako:** v2.1.0 (`js/pako_inflate.min.js`) - Used for Tracee log decompression.
*   **CryptoJS:** v4.2.0 (`js/crypto-js.min.js`)
*   **Hexdump:** (`js/hexdump.js`) - Local utility for rendering binary data.

---
*Note: Versions should be updated in this README whenever the underlying files are replaced.*
