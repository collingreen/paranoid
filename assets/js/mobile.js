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

  document.addEventListener("deviceready", function () {
    // display cordova required items
    if (window.cordova) {
      $('.cordova_required').css('display', 'block');
    }
  });

  document.addEventListener('DOMContentLoaded', function () {
    // open getting started modal on the first load
    var storageKey = 'paranoid_getting_started_1';
    if (localStorage && !localStorage.getItem(storageKey)) {
      localStorage.setItem(storageKey, true);
      showGettingStarted();
    }
  }, false);

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


  // open modal wrapper -- closes other modals, resizes on mobile
  function openModal (selector) {
    if (!window.openModals) {
      window.openModals = [];
    }

    for (var i = 0; i < window.openModals.length; i++) {
      window.openModals[i].modal('hide');
    }
    window.openModals = [];

    var modal = $(selector).modal({show: true});
    resizeModal(modal);
    window.openModals.push(modal);
  };

  // TODO: abstract this and just have one modal that
  // changes content
  $('.instructions_button').on('click', function () {
    openModal('#instructions_modal');
  });

  $('.creating_strong_passphrases').on('click', function () {
    openModal('#creating_passphrases_modal');
  });

  $('.frequently_asked_questions').on('click', function () {
    openModal('#faq_modal');
  });

  $('.getting_started').on('click', function () {
    showGettingStarted();
  });

  $('.about_button').on('click', function () {
    openModal('#about_modal');
  });

  $('.upgrade_button').on('click', function () {
    openModal('#upgrade_modal');
  });

  $('.login_button').on('click', function () {
    notify('logging in');
    $.post({
      url: 'http://10.0.0.10:8080/login',
      complete: function (res) {
        console.log('response', res);
        alert(res);
      }
    });
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

  function showGettingStarted() {
    openModal('#getting_started_modal');
  }

})();
