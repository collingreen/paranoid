function notify (text, title, style) {
  $('#notifications').notifyr({
    message: text,
    location: 'bottom-right',
    title: title || 'Paranoid Password',
    classes: [style]
  });

  // hack to fix notification hiding on mobile
  $('#notifications').css('opacity', 1);
  $('#notifications').on('notification-remove-complete', function() {
    $('#notifications').css('opacity', 0);
    $('#notifications').off('notification-remove-complete');
  });
}
