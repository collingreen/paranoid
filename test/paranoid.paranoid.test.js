var expect = require('chai').expect;
var rewire = require('rewire');
var paranoid = rewire('../lib/paranoid.js');
var testData = require('./testData.js');

// Controls the number of master passwords and paranoid locks
// that get permuted. End result will test
// TEST_SIZE * TEST_SIZE * <number of test domains> different
// generation combinations.
var TEST_SIZE = 10;

var randomWords = testData.randomWords;
var testRealDomains = testData.testRealDomains;

describe('Paranoid', function(){
  describe('#PasswordRules', function(){

    for (var i = 0, iEnd = TEST_SIZE; i < iEnd; i++) {
      var masterPassword = randomWords[i];

      for (var j = TEST_SIZE, jEnd = TEST_SIZE * 2; j < jEnd; j++) {
        var paranoidLock = randomWords[j];

        for (var k = 0, kEnd = testRealDomains.length; k < kEnd; k++) {
          var uri = testRealDomains[k];

          // generate paranoid passwords
          var paranoidPassword = paranoid.paranoid({
            masterPassword: masterPassword,
            paranoidLock: paranoidLock,
            uri: uri
          });

          it('should always have at least one lowercase character', function () {
            expect(paranoidPassword.match(/[a-z]/)).to.not.equal(null);
          });

          it('should always have at least one uppercase character', function () {
            expect(paranoidPassword.match(/[A-Z]/)).to.not.equal(null);
          });

          it('should always have at least one numeric character', function () {
            expect(paranoidPassword.match(/[0-9]/)).to.not.equal(null);
          });

        } // end for k in testRealDomains
      } // end j in TEST_SIZE in randomWords
    } // end i in TEST_SIZE in randomWords
  });

  describe('#Parameters', function(){
    var master = randomWords[0];
    var lock = randomWords[1];
    var uri = testRealDomains[0];

    var withDefaults = paranoid.paranoid({
      masterPassword: master,
      paranoidLock: lock,
      uri: uri
    });

    it('should allow masterPassword or master', function () {
      // generate paranoid passwords
      var withMaster = paranoid.paranoid({
        master: master,
        paranoidLock: lock,
        uri: uri
      });

      expect(withMaster).to.equal(withDefaults);
    });

    it('should allow paranoidLock or lock', function () {
      var withLock = paranoid.paranoid({
        masterPassword: master,
        lock: lock,
        uri: uri
      });
      expect(withLock).to.equal(withDefaults);
    });

    it('should allow uri or target', function () {
      var withTarget = paranoid.paranoid({
        masterPassword: master,
        paranoidLock: lock,
        target: uri
      });
      expect(withTarget).to.equal(withDefaults);
    });

    it('should allow master and lock', function () {
      var withMasterAndLock = paranoid.paranoid({
        master: master,
        lock: lock,
        uri: uri
      });
      expect(withMasterAndLock).to.equal(withDefaults);
    });

    it('should allow master and lock and target', function () {
      var withMasterAndLockAndTarget = paranoid.paranoid({
        master: master,
        lock: lock,
        target: uri
      });
      expect(withMasterAndLockAndTarget).to.equal(withDefaults);
    });
  }); // end describe #Parameters

}); // end describe Paranoid
