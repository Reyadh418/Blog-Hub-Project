(function () {
    function toBool(value) {
        return value === true || value === 1 || value === '1';
    }

    function getPostAuthorState(post) {
        const safePost = post || {};
        const isAdminPost = toBool(safePost.is_admin_post) || safePost.author_id === null;
        const authorIsAdmin = toBool(safePost.author_is_admin);
        const authorEmailVerified = toBool(safePost.author_email_verified);
        const authorVerifiedByAdmin = toBool(safePost.author_is_verified_by_admin);
        return {
            isAdminPost,
            authorIsAdmin,
            authorEmailVerified,
            authorVerifiedByAdmin,
        };
    }

    function resolveTrustBadge(post) {
        const state = getPostAuthorState(post);
        if (state.isAdminPost || state.authorIsAdmin) {
            return { text: 'Admin', className: 'admin' };
        }
        if (!state.authorEmailVerified) {
            return { text: 'Unverified', className: 'unverified' };
        }
        if (state.authorVerifiedByAdmin) {
            return { text: 'Verified', className: 'verified' };
        }
        return { text: 'Community', className: 'community' };
    }

    window.PostTrust = {
        toBool,
        getPostAuthorState,
        resolveTrustBadge,
    };
})();