/**
 * Premium Page Transitions
 * Include this script in all pages for smooth navigation
 */

(function () {
    'use strict';

    // Inject transition overlay and styles if not present
    function injectTransitionElements() {
        // Check if overlay already exists
        if (document.getElementById('pageTransitionOverlay')) return;

        // Inject CSS
        const style = document.createElement('style');
        style.id = 'pageTransitionStyles';
        style.textContent = `
            .page-transition-overlay {
                position: fixed;
                inset: 0;
                z-index: 99999;
                pointer-events: none;
                background: linear-gradient(135deg, #1e3a5f 0%, #2d5a8c 100%);
                opacity: 0;
                transition: opacity 0.35s cubic-bezier(0.4, 0, 0.2, 1);
            }

            .page-transition-overlay.active {
                opacity: 1;
                pointer-events: all;
            }

            .page-transition-overlay .transition-content {
                position: absolute;
                top: 50%;
                left: 50%;
                transform: translate(-50%, -50%);
                text-align: center;
                color: #ffffff;
            }

            .page-transition-overlay .transition-spinner {
                width: 40px;
                height: 40px;
                border: 3px solid rgba(255, 255, 255, 0.2);
                border-top-color: #d4a574;
                border-radius: 50%;
                animation: transitionSpin 0.8s linear infinite;
                margin: 0 auto 16px;
            }

            .page-transition-overlay .transition-text {
                font-size: 1rem;
                font-weight: 500;
                letter-spacing: 1px;
                opacity: 0.9;
            }

            @keyframes transitionSpin {
                to { transform: rotate(360deg); }
            }

            /* Page enter animation */
            body.page-transition-enter {
                animation: pageEnter 0.4s cubic-bezier(0.4, 0, 0.2, 1) forwards;
            }

            @keyframes pageEnter {
                from {
                    opacity: 0;
                }
                to {
                    opacity: 1;
                }
            }
        `;
        document.head.appendChild(style);

        // Inject overlay
        const overlay = document.createElement('div');
        overlay.id = 'pageTransitionOverlay';
        overlay.className = 'page-transition-overlay';
        overlay.innerHTML = `
            <div class="transition-content">
                <div class="transition-spinner"></div>
                <div class="transition-text">Loading...</div>
            </div>
        `;
        document.body.insertBefore(overlay, document.body.firstChild);

        // Add enter animation class
        document.body.classList.add('page-transition-enter');
    }

    // Navigate with transition
    function navigateWithTransition(url) {
        const overlay = document.getElementById('pageTransitionOverlay');
        if (!overlay) {
            window.location.href = url;
            return;
        }
        overlay.classList.add('active');
        setTimeout(() => {
            window.location.href = url;
        }, 280);
    }

    // Intercept internal link clicks
    function handleLinkClick(e) {
        const link = e.target.closest('a[href]');
        if (!link) return;

        const href = link.getAttribute('href');
        if (!href) return;

        // Skip external links, anchors, special protocols
        if (
            href.startsWith('http') ||
            href.startsWith('#') ||
            href.startsWith('javascript:') ||
            href.startsWith('mailto:') ||
            href.startsWith('tel:')
        ) return;

        // Skip links with target="_blank"
        if (link.target === '_blank') return;

        e.preventDefault();
        navigateWithTransition(href);
    }

    // Handle browser back/forward
    function handlePageShow(e) {
        const overlay = document.getElementById('pageTransitionOverlay');
        if (e.persisted && overlay) {
            overlay.classList.remove('active');
        }
    }

    // Initialize
    function init() {
        injectTransitionElements();
        document.addEventListener('click', handleLinkClick);
        window.addEventListener('pageshow', handlePageShow);

        // Expose globally for programmatic navigation
        window.navigateWithTransition = navigateWithTransition;
    }

    // Run on DOM ready
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', init);
    } else {
        init();
    }
})();
