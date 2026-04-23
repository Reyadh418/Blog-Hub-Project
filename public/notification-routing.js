(function attachNotificationRouting(globalScope) {
  function asLowerText(value) {
    return (value || '').toString().toLowerCase();
  }

  function resolveDestination(notification, currentUser) {
    if (notification && notification.post_id) {
      return `/post.html?id=${notification.post_id}`;
    }

    const type = asLowerText(notification && notification.type);
    const message = asLowerText(notification && notification.message);

    if (type === 'verification_request') {
      return '/admin-profile.html#verificationRequestsSection';
    }

    if (type === 'verification_complete' || type === 'verification_rejected') {
      return '/profile.html#verificationCard';
    }

    const roleOrProfileUpdate =
      type === 'promotion' ||
      type === 'demotion' ||
      type === 'profile' ||
      message.includes('promoted to admin') ||
      message.includes('demoted') ||
      message.includes('super admin');

    if (roleOrProfileUpdate) {
      if (currentUser && currentUser.isAdmin) {
        return currentUser.isSuperAdmin ? '/admin-profile.html' : '/promoted-admin-profile.html';
      }
      return '/profile.html';
    }

    return null;
  }

  globalScope.NotificationRouting = {
    resolveDestination,
  };
})(window);
