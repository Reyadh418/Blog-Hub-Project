(function () {
    const BRAND_CONTRACT_VERSION = '1.0.0';
    const DEV_MODE =
        typeof window !== 'undefined' &&
        (window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1');

    const BRAND_EXPRESSION = Object.freeze({
        principle: 'Structured Inspiration',
        statement:
            'Clear product structure with editorial emotional depth, grounded in trust and personal voice.',
        tone: Object.freeze(['Clear', 'Emotional', 'Trustworthy', 'Personal']),
        visualDirection: Object.freeze({
            saasLayer: Object.freeze([
                'Navigation clarity',
                'Fast scanability',
                'Strong hierarchy',
                'Mobile readability',
            ]),
            editorialLayer: Object.freeze([
                'Powerful headline composition',
                'Intentional pull-quote rhythm',
                'Calm whitespace posture',
                'Sans-first titles until serif rollout',
            ]),
        }),
        contentPosture: Object.freeze({
            headlineVoice: 'Specific, useful, and emotionally honest.',
            subheadVoice: 'Context-first, concise, confidence-building.',
            quoteRule: 'Use quotes only when they deepen meaning or add proof.',
            credibilityCue: 'Show standards and author intent without marketing hype.',
        }),
    });

    const PAGE_CONTEXT = Object.freeze({
        index: Object.freeze({
            saasRole: 'Discovery and orientation',
            editorialRole: 'Set publication voice and emotional promise',
            emotionalOutcome: 'Grounded motivation',
        }),
        post: Object.freeze({
            saasRole: 'Long-form reading and interaction',
            editorialRole: 'Narrative depth with practical reflection',
            emotionalOutcome: 'Clarity and resonance',
        }),
        profile: Object.freeze({
            saasRole: 'Identity and contribution management',
            editorialRole: 'Author credibility and continuity',
            emotionalOutcome: 'Trust and ownership',
        }),
        'create-post': Object.freeze({
            saasRole: 'Structured publishing workflow',
            editorialRole: 'Encourage thoughtful, useful storytelling',
            emotionalOutcome: 'Confident expression',
        }),
        bookmarks: Object.freeze({
            saasRole: 'Saved reading management',
            editorialRole: 'Curate meaningful story follow-up',
            emotionalOutcome: 'Intentional continuity',
        }),
        login: Object.freeze({
            saasRole: 'Secure account access',
            editorialRole: 'Return readers to story flow quickly',
            emotionalOutcome: 'Confidence',
        }),
        register: Object.freeze({
            saasRole: 'Account onboarding',
            editorialRole: 'Invite thoughtful contributors',
            emotionalOutcome: 'Belonging',
        }),
        'edit-profile': Object.freeze({
            saasRole: 'Profile maintenance',
            editorialRole: 'Strengthen author credibility',
            emotionalOutcome: 'Ownership',
        }),
        'verify-email': Object.freeze({
            saasRole: 'Security verification',
            editorialRole: 'Protect trusted community quality',
            emotionalOutcome: 'Safety',
        }),
        'admin-profile': Object.freeze({
            saasRole: 'Administrative oversight',
            editorialRole: 'Maintain publication standards',
            emotionalOutcome: 'Stewardship',
        }),
        'promoted-admin-profile': Object.freeze({
            saasRole: 'Moderator workspace',
            editorialRole: 'Support responsible story governance',
            emotionalOutcome: 'Responsibility',
        }),
        'admin-management': Object.freeze({
            saasRole: 'Admin role governance',
            editorialRole: 'Protect leadership integrity',
            emotionalOutcome: 'Control',
        }),
        'admin-users': Object.freeze({
            saasRole: 'User directory and moderation access',
            editorialRole: 'Support fair community oversight',
            emotionalOutcome: 'Clarity',
        }),
        'view-profile': Object.freeze({
            saasRole: 'User profile review',
            editorialRole: 'Assess author contribution context',
            emotionalOutcome: 'Trust',
        }),
    });

    const PAGE_KEYS = Object.freeze(Object.keys(PAGE_CONTEXT));

    const BRAND_COPY = Object.freeze({
        'index.nav.stories': 'Stories',
        'index.hero.kicker': 'Blog Hub Journal',
        'index.hero.headline.a': 'Think Clearly.',
        'index.hero.headline.b': 'Grow Intentionally.',
        'index.hero.subtitle': 'Clean thinking. Real stories. Better decisions.',
        'index.hero.mission':
            'We publish practical ideas and real stories that help people think clearly, grow consistently, and build a more disciplined life.',
        'index.about.title': 'About This Publication',
        'index.about.kicker': 'Structured Inspiration',
        'index.about.trust':
            'Editorial standard: each published story should include lived context, one practical takeaway, and respectful language for readers at every stage.',
        'index.category.education': 'Education',
        'index.category.stories': 'Stories',
        'index.category.mindset': 'Mindset',
        'index.category.lessons': 'Lessons',
        'index.search.placeholder': 'Search title, category, tags, or @author',

        'post.back': '← Back to Stories',
        'post.loading': 'Loading post...',
        'post.trust':
            'Publication promise: this story is shared for clarity and growth, and community responses are moderated for respectful, useful discussion.',
        'post.reaction.helpful': 'Was this helpful?',
        'post.comments.loginPrompt': '📝 Log in to join the conversation',
        'post.error.back': '← Back to Stories',

        'profile.loading': 'Loading profile...',
        'profile.trust':
            'Author trust signal: profiles highlight real contribution history so readers can follow consistent voices and thoughtful growth.',
        'profile.avatar.title': 'Choose your avatar',
        'profile.avatar.subtitle': 'Pick a premium badge. Changes apply instantly after confirm.',

        'create.subtitle': 'Share your thoughts with the world',
        'create.trust':
            'Publishing standard: aim for honest context, one actionable takeaway, and language that supports thoughtful community discussion.',
        'create.verify.title': 'Verify Your Email (Optional for now)',
        'create.category.label': 'Primary Category',
        'create.category.note': 'Use one of the four standard publication categories.',
        'create.tags.label': 'Supporting Tags (optional, comma-separated)',
        'create.tags.placeholder': 'e.g. habits, reflection, productivity',

        'login.back': '← Back to Stories',
        'register.back': '← Back to Stories',
        'bookmarks.back': '← Back to Stories',
        'verify.continue': 'Continue to Stories Hub',

        'profile.nav.brand': '📝 Stories Hub',
        'profile.nav.newStory': 'New Story',
        'promoted.nav.brand': '📝 Stories Hub',
        'promoted.nav.newStory': 'New Story',
        'promoted.home.back': '🏠 Back to Stories',
        'admin.nav.brand': '📝 Stories Hub',
        'admin.nav.newStory': 'New Story',
        'admin.home.back': '🏠 Back to Stories',
        'adminUsers.home': '🏠 Stories',
    });

    function ensureMeta(name, content) {
        if (!content) return;
        let tag = document.querySelector(`meta[name="${name}"]`);
        if (!tag) {
            tag = document.createElement('meta');
            tag.setAttribute('name', name);
            document.head.appendChild(tag);
        }
        tag.setAttribute('content', content);
    }

    function brandWarn(message, detail) {
        if (!DEV_MODE || typeof console === 'undefined') return;
        console.warn('[brand-expression]', message, detail || '');
    }

    function getBrandCopy(key, fallback = '') {
        if (!key) return fallback;
        const value = BRAND_COPY[key];
        if (typeof value === 'undefined') {
            brandWarn('Missing copy key', key);
            return fallback;
        }
        return value;
    }

    const PILLAR_ACCENT_MAP = Object.freeze({
        education: 'education',
        stories: 'stories',
        story: 'stories',
        mindset: 'mindset',
        lessons: 'lessons',
        lesson: 'lessons',
        discipline: 'discipline',
        'real stories': 'stories',
        career: 'career',
        guide: 'career',
        guides: 'career',
    });

    function normalizeCategoryToken(value = '') {
        return (value || '').toString().trim().toLowerCase();
    }

    function getPillarAccentKey(category = '') {
        const normalized = normalizeCategoryToken(category);
        return PILLAR_ACCENT_MAP[normalized] || 'stories';
    }

    function applyPillarAccent(element, category = '') {
        if (!element || !element.setAttribute) return;
        const accent = getPillarAccentKey(category);
        element.setAttribute('data-accent', accent);
        if (category) element.setAttribute('data-category', category);
    }

    function applyBrandFoundation() {
        const pageKey = document.body?.dataset?.brandPage;
        const pageConfig = pageKey ? PAGE_CONTEXT[pageKey] : null;

        document.documentElement.dataset.brandPrinciple = 'structured-inspiration';
        document.documentElement.dataset.brandTone = BRAND_EXPRESSION.tone.join('|').toLowerCase();

        ensureMeta('brand-principle', BRAND_EXPRESSION.principle);
        ensureMeta('brand-statement', BRAND_EXPRESSION.statement);
        ensureMeta('brand-contract-version', BRAND_CONTRACT_VERSION);

        document.documentElement.dataset.brandContractVersion = BRAND_CONTRACT_VERSION;
        document.documentElement.dataset.brandSerifPolicy = 'deferred';

        if (pageKey && !pageConfig) {
            brandWarn('Unknown data-brand-page key', pageKey);
        }

        if (pageConfig) {
            document.documentElement.dataset.brandPageRole = pageConfig.saasRole;
            ensureMeta('brand-page-role', `${pageConfig.saasRole}; ${pageConfig.editorialRole}`);
            ensureMeta('brand-emotional-outcome', pageConfig.emotionalOutcome);
        }
    }

    function applyBrandCopy() {
        const nodes = document.querySelectorAll('[data-brand-copy]');
        let missingCount = 0;

        nodes.forEach((node) => {
            const key = node.getAttribute('data-brand-copy');
            if (!key) return;
            const value = getBrandCopy(key);
            if (!value) {
                missingCount += 1;
                return;
            }
            node.textContent = value;
        });

        if (missingCount > 0) {
            brandWarn('Unresolved brand copy bindings', missingCount);
        }

        const placeholderNodes = document.querySelectorAll('[data-brand-placeholder]');
        let placeholderMissingCount = 0;
        placeholderNodes.forEach((node) => {
            const key = node.getAttribute('data-brand-placeholder');
            if (!key) return;
            const value = getBrandCopy(key);
            if (!value) {
                placeholderMissingCount += 1;
                return;
            }
            node.setAttribute('placeholder', value);
        });

        if (placeholderMissingCount > 0) {
            brandWarn('Unresolved brand placeholder bindings', placeholderMissingCount);
        }

        return {
            total: nodes.length + placeholderNodes.length,
            missing: missingCount + placeholderMissingCount,
        };
    }

    const BRAND_RUNTIME = Object.freeze({
        version: BRAND_CONTRACT_VERSION,
        pageKeys: PAGE_KEYS,
        serifPolicy: 'deferred',
    });

    window.BRAND_EXPRESSION = BRAND_EXPRESSION;
    window.BRAND_PAGE_CONTEXT = PAGE_CONTEXT;
    window.BRAND_COPY = BRAND_COPY;
    window.BRAND_RUNTIME = BRAND_RUNTIME;
    window.getBrandCopy = getBrandCopy;
    window.normalizeCategoryToken = normalizeCategoryToken;
    window.getPillarAccentKey = getPillarAccentKey;
    window.applyPillarAccent = applyPillarAccent;
    window.applyBrandFoundation = applyBrandFoundation;
    window.applyBrandCopy = applyBrandCopy;

    function injectLiquidGlassStyles() {
        if (!document.querySelector('link[href*="liquid-glass.css"]')) {
            const link = document.createElement('link');
            link.rel = 'stylesheet';
            link.href = '/liquid-glass.css';
            document.head.appendChild(link);
        }
    }

    function injectLiquidGlassBlobs() {
        if (!document.querySelector('.glass-blobs-container')) {
            const container = document.createElement('div');
            container.className = 'glass-blobs-container';
            container.innerHTML = `
                <div class="glass-blob glass-blob-1"></div>
                <div class="glass-blob glass-blob-2"></div>
                <div class="glass-blob glass-blob-3"></div>
            `;
            if (document.body) {
                document.body.insertBefore(container, document.body.firstChild);
            }
        }
    }

    if (document.head) {
        injectLiquidGlassStyles();
    } else {
        document.addEventListener('DOMContentLoaded', injectLiquidGlassStyles);
    }

    if (document.readyState === 'loading') {
        document.addEventListener(
            'DOMContentLoaded',
            () => {
                applyBrandFoundation();
                applyBrandCopy();
                injectLiquidGlassBlobs();
            },
            { once: true }
        );
    } else {
        applyBrandFoundation();
        applyBrandCopy();
        injectLiquidGlassBlobs();
    }
})();
