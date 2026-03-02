(function () {
    function escapeHtml(text) {
        return String(text || '').replace(/[&<>"']/g, function (char) {
            switch (char) {
                case '&': return '&amp;';
                case '<': return '&lt;';
                case '>': return '&gt;';
                case '"': return '&quot;';
                case "'": return '&#039;';
                default: return char;
            }
        });
    }

    function normalize(text) {
        return String(text || '').replace(/\r\n?/g, '\n');
    }

    function stripMarkdown(text) {
        const input = normalize(text)
            .replace(/```[\s\S]*?```/g, ' ')
            .replace(/`([^`]+)`/g, '$1')
            .replace(/!\[([^\]]*)\]\(([^)]+)\)/g, '$1')
            .replace(/\[([^\]]+)\]\(([^)]+)\)/g, '$1')
            .replace(/\*\*([^*]+)\*\*/g, '$1')
            .replace(/__([^_]+)__/g, '$1')
            .replace(/\*([^*]+)\*/g, '$1')
            .replace(/_([^_]+)_/g, '$1')
            .replace(/^#{1,6}\s+/gm, '')
            .replace(/^>\s?/gm, '')
            .replace(/^[-*+]\s+/gm, '')
            .replace(/^\d+\.\s+/gm, '')
            .replace(/~~([^~]+)~~/g, '$1');

        return input.replace(/\s+/g, ' ').trim();
    }

    function excerpt(text, maxLength) {
        const source = stripMarkdown(text);
        if (source.length <= maxLength) return source;
        return source.slice(0, maxLength).trimEnd() + '...';
    }

    function safeUrl(raw) {
        const value = String(raw || '').trim();
        if (!value) return '';
        if (/^(https?:\/\/|mailto:)/i.test(value)) return value;
        return '';
    }

    function renderInline(text) {
        const tokens = [];
        let source = String(text || '');

        source = source.replace(/`([^`\n]+)`/g, function (_, code) {
            const token = `__TF_CODE_${tokens.length}__`;
            tokens.push(`<code>${escapeHtml(code)}</code>`);
            return token;
        });

        source = source.replace(/\[([^\]]+)\]\(([^)\s]+)\)/g, function (_, label, url) {
            const token = `__TF_LINK_${tokens.length}__`;
            const safe = safeUrl(url);
            if (!safe) {
                tokens.push(escapeHtml(label));
            } else {
                tokens.push(`<a href="${escapeHtml(safe)}" target="_blank" rel="noopener noreferrer">${escapeHtml(label)}</a>`);
            }
            return token;
        });

        let html = escapeHtml(source);

        html = html
            .replace(/\*\*([^*]+)\*\*/g, '<strong>$1</strong>')
            .replace(/__([^_]+)__/g, '<strong>$1</strong>')
            .replace(/\*([^*]+)\*/g, '<em>$1</em>')
            .replace(/_([^_]+)_/g, '<em>$1</em>')
            .replace(/~~([^~]+)~~/g, '<del>$1</del>')
            .replace(/@([a-zA-Z0-9._-]{3,32})/g, '<span class="mention">@$1</span>');

        tokens.forEach(function (value, index) {
            html = html.replace(`__TF_CODE_${index}__`, value);
            html = html.replace(`__TF_LINK_${index}__`, value);
        });

        return html;
    }

    function paragraphFromLines(lines, paragraphClass) {
        const merged = lines.join('\n').trim();
        if (!merged) return '';
        return `<p class="${paragraphClass}">${renderInline(merged).replace(/\n/g, '<br>')}</p>`;
    }

    function toHtml(raw, options) {
        const source = normalize(raw);
        if (!source.trim()) return '';

        const classNames = Object.assign(
            {
                paragraph: 'tf-paragraph',
                heading: 'tf-heading',
                blockquote: 'tf-blockquote',
                list: 'tf-list',
                listItem: 'tf-list-item',
                codeBlock: 'tf-code-block'
            },
            (options && options.classNames) || {}
        );

        const lines = source.split('\n');
        const html = [];
        let i = 0;

        while (i < lines.length) {
            const line = lines[i];
            const trimmed = line.trim();

            if (!trimmed) {
                i += 1;
                continue;
            }

            if (/^```/.test(trimmed)) {
                const codeLines = [];
                i += 1;
                while (i < lines.length && !/^```/.test(lines[i].trim())) {
                    codeLines.push(lines[i]);
                    i += 1;
                }
                if (i < lines.length && /^```/.test(lines[i].trim())) i += 1;
                html.push(`<pre class="${classNames.codeBlock}"><code>${escapeHtml(codeLines.join('\n'))}</code></pre>`);
                continue;
            }

            const headingMatch = trimmed.match(/^(#{1,3})\s+(.+)$/);
            if (headingMatch) {
                const level = Math.min(3, headingMatch[1].length);
                html.push(`<h${level} class="${classNames.heading}">${renderInline(headingMatch[2])}</h${level}>`);
                i += 1;
                continue;
            }

            if (/^>\s?/.test(trimmed)) {
                const quoteLines = [];
                while (i < lines.length && /^\s*>\s?/.test(lines[i])) {
                    quoteLines.push(lines[i].replace(/^\s*>\s?/, ''));
                    i += 1;
                }
                html.push(`<blockquote class="${classNames.blockquote}">${paragraphFromLines(quoteLines, classNames.paragraph)}</blockquote>`);
                continue;
            }

            if (/^[-*+]\s+/.test(trimmed)) {
                const items = [];
                while (i < lines.length && /^\s*[-*+]\s+/.test(lines[i])) {
                    items.push(lines[i].replace(/^\s*[-*+]\s+/, ''));
                    i += 1;
                }
                html.push(`<ul class="${classNames.list}">${items.map(item => `<li class="${classNames.listItem}">${renderInline(item)}</li>`).join('')}</ul>`);
                continue;
            }

            if (/^\d+\.\s+/.test(trimmed)) {
                const items = [];
                while (i < lines.length && /^\s*\d+\.\s+/.test(lines[i])) {
                    items.push(lines[i].replace(/^\s*\d+\.\s+/, ''));
                    i += 1;
                }
                html.push(`<ol class="${classNames.list}">${items.map(item => `<li class="${classNames.listItem}">${renderInline(item)}</li>`).join('')}</ol>`);
                continue;
            }

            const paragraphLines = [];
            while (i < lines.length && lines[i].trim()) {
                paragraphLines.push(lines[i]);
                i += 1;
            }
            html.push(paragraphFromLines(paragraphLines, classNames.paragraph));
        }

        return html.join('');
    }

    function surroundSelection(textarea, prefix, suffix, placeholder) {
        if (!textarea) return;
        const start = textarea.selectionStart || 0;
        const end = textarea.selectionEnd || 0;
        const value = textarea.value || '';
        const selected = value.slice(start, end);
        const content = selected || placeholder;
        const replacement = `${prefix}${content}${suffix}`;
        textarea.value = value.slice(0, start) + replacement + value.slice(end);

        const cursorStart = start + prefix.length;
        const cursorEnd = cursorStart + content.length;
        textarea.focus();
        textarea.setSelectionRange(cursorStart, cursorEnd);
        textarea.dispatchEvent(new Event('input', { bubbles: true }));
    }

    function insertLinePrefix(textarea, prefix) {
        if (!textarea) return;
        const start = textarea.selectionStart || 0;
        const end = textarea.selectionEnd || 0;
        const value = textarea.value || '';
        const selected = value.slice(start, end) || 'List item';
        const replaced = selected
            .split('\n')
            .map((line) => `${prefix}${line}`)
            .join('\n');

        textarea.value = value.slice(0, start) + replaced + value.slice(end);
        textarea.focus();
        textarea.setSelectionRange(start, start + replaced.length);
        textarea.dispatchEvent(new Event('input', { bubbles: true }));
    }

    function applyFormat(textarea, action) {
        switch (action) {
            case 'bold':
                surroundSelection(textarea, '**', '**', 'bold text');
                break;
            case 'italic':
                surroundSelection(textarea, '*', '*', 'italic text');
                break;
            case 'h2':
                insertLinePrefix(textarea, '## ');
                break;
            case 'quote':
                insertLinePrefix(textarea, '> ');
                break;
            case 'list':
                insertLinePrefix(textarea, '- ');
                break;
            case 'link':
                surroundSelection(textarea, '[', '](https://example.com)', 'link text');
                break;
            case 'code':
                surroundSelection(textarea, '`', '`', 'code');
                break;
            default:
                break;
        }
    }

    function bindToolbar(toolbar, textarea) {
        if (!toolbar || !textarea) return;
        toolbar.addEventListener('click', function (event) {
            const button = event.target.closest('button[data-format]');
            if (!button) return;
            event.preventDefault();
            applyFormat(textarea, button.dataset.format);
        });
    }

    window.TextFormatting = {
        escapeHtml,
        stripMarkdown,
        excerpt,
        toHtml,
        applyFormat,
        bindToolbar
    };
})();
