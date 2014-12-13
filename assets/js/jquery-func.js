(function () {
    $('body').scrollspy({
      target: '#navbar-main',
      offset: $('.navbar-height').height()
    });

    $(window).on('load', function () {
      $('body').scrollspy('refresh')
    });

    $('#navbar-main [href=#]').click(function (e) {
      e.preventDefault();
    });

    $('#navbar-main').on('activate.bs.scrollspy', function () {
      alert('navbar scrollspy');
    });
})();
