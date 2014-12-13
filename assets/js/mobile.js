// call after showing a modal to resize it to fit on mobile
function resizeModal(modal) {

  // calculate max size for body
  var header = modal.find('.modal-header');
  var footer = modal.find('.modal-footer');
  var extraPadding = 75;
  var bodyHeight = $(window).height() -
                    header.outerHeight() -
                    footer.outerHeight() -
                    extraPadding;

  // if body size is bigger than ideal size
  var modalBody = modal.find('.modal-body');

  if (modalBody.outerHeight() > bodyHeight) {
    modalBody.css({
      'max-height': bodyHeight,
      'max-width': $(window).width()
    });
  } else {
    var modalHeight = modal.outerHeight();
    var padding = $(window).height() - modalHeight;
    modal.css({top: padding / 2});
  }
};

(function() {

  // // overwrite model function to always call resizeModal after
  // var originalModal = $.fn.modal;
  // // var defaults = $.extend({}, $.fn.modal.defaults);
  // var defaults = $.extend({}, originalModal.defaults);
  // $.fn.modal = function(options) {
  //   options = $.extend(defaults, options);
  //   // this.each(function() {});
  //   var modal = originalModal.call(this, options);
  //   resizeModal(modal);
  //   return modal;
  // };

  // TODO: abstract this and just have one modal that
  // changes content
  $('.instructions_button').on('click', function () {
    var modal = $('#instructions_modal').modal({show: true});
    resizeModal(modal);
  });

  $('.about_button').on('click', function () {
    var modal = $('#about_modal').modal({show: true});
    resizeModal(modal);
  });

  $('.upgrade_button').on('click', function () {
    var modal = $('#upgrade_modal').modal({show: true});
    resizeModal(modal);
  });

  $('.login_button').on('click', function () {
    var modal = $('#login_modal').modal({show: true});
    resizeModal(modal);
  });

  $('.navbar-header .navbar-toggle').on('click', function (e) {
    toggleOverlay();
    return false;
  });

  // from https://github.com/codrops/FullscreenOverlayStyles
  var overlay = document.querySelector( 'div.overlay' ),
    transEndEventNames = {
      'WebkitTransition': 'webkitTransitionEnd',
      'MozTransition': 'transitionend',
      'OTransition': 'oTransitionEnd',
      'msTransition': 'MSTransitionEnd',
      'transition': 'transitionend'
    },
    transEndEventName = transEndEventNames[ Modernizr.prefixed('transition') ],
    support = { transitions : Modernizr.csstransitions };

  function toggleOverlay() {
    if( classie.has( overlay, 'open' ) ) {
      classie.remove( overlay, 'open' );
      classie.add( overlay, 'close' );
      var onEndTransitionFn = function( ev ) {
        if( support.transitions ) {
          if( ev.propertyName !== 'visibility' ) return;
          this.removeEventListener( transEndEventName, onEndTransitionFn );
        }
        classie.remove( overlay, 'close' );
      };
      if( support.transitions ) {
        overlay.addEventListener( transEndEventName, onEndTransitionFn );
      }
      else {
        onEndTransitionFn();
      }
    }
    else if( !classie.has( overlay, 'close' ) ) {
      classie.add( overlay, 'open' );
    }
  }
})();
