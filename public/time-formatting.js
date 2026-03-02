(function () {
    function parseServerTimestamp(dateString = '') {
        const raw = (dateString || '').toString().trim();
        if (!raw) return NaN;
        const normalized = raw.includes('T') ? raw : raw.replace(' ', 'T');
        const hasZone = /(?:Z|[+\-]\d{2}:\d{2})$/i.test(normalized);
        const withZone = hasZone ? normalized : `${normalized}Z`;
        const ms = Date.parse(withZone);
        return Number.isFinite(ms) ? ms : NaN;
    }

    function formatDate(dateString, options = { year: 'numeric', month: 'short', day: 'numeric' }) {
        const parsed = parseServerTimestamp(dateString);
        const date = Number.isFinite(parsed) ? new Date(parsed) : new Date(dateString);
        return date.toLocaleDateString('en-US', options);
    }

    function formatRelative(dateString, dateOptions = { year: 'numeric', month: 'short', day: 'numeric' }) {
        const then = parseServerTimestamp(dateString);
        if (!Number.isFinite(then)) return formatDate(dateString, dateOptions);
        const diffMin = Math.floor(Math.max(0, Date.now() - then) / 60000);
        if (diffMin < 60) {
            const minuteValue = Math.max(1, diffMin);
            return `${minuteValue} min ago`;
        }
        const diffHr = Math.floor(diffMin / 60);
        if (diffHr < 24) {
            return `${diffHr} hour${diffHr === 1 ? '' : 's'} ago`;
        }
        return formatDate(dateString, dateOptions);
    }

    window.TimeFormatting = {
        parseServerTimestamp,
        formatDate,
        formatRelative,
        timeAgo: formatRelative,
    };
})();