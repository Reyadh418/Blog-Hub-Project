(function () {
    const MUTATING = new Set(["POST", "PUT", "PATCH", "DELETE"]);
    const originalFetch = window.fetch.bind(window);
    let csrfToken = null;

    async function ensureCsrfToken() {
        if (csrfToken) return csrfToken;
        try {
            const resp = await originalFetch('/api/auth/csrf', { credentials: 'same-origin' });
            if (resp.ok) {
                const headerToken = resp.headers.get('x-csrf-token');
                if (headerToken) csrfToken = headerToken;
                if (!csrfToken) {
                    const data = await resp.json().catch(() => ({}));
                    csrfToken = data.token || null;
                }
            }
        } catch (e) {
            console.warn('CSRF token fetch failed', e);
        }
        return csrfToken;
    }

    window.ensureCsrfToken = ensureCsrfToken;

    window.fetch = async function (resource, options = {}) {
        const opts = { ...options };
        opts.headers = new Headers(opts.headers || {});
        const method = (opts.method || 'GET').toUpperCase();
        if (MUTATING.has(method)) {
            const token = await ensureCsrfToken();
            if (token) {
                opts.headers.set('x-csrf-token', token);
            }
        }
        const resp = await originalFetch(resource, opts);
        const headerToken = resp && resp.headers ? resp.headers.get('x-csrf-token') : null;
        if (headerToken) csrfToken = headerToken;
        return resp;
    };

    // Preload token on page load (non-blocking)
    ensureCsrfToken();
})();
