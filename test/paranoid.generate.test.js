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

describe('Paranoid.generate', function(){

  describe('#Unique', function(){

    var passwords = [];
    var duplicates = {};

    for (var i = 0, iEnd = TEST_SIZE; i < iEnd; i++) {
      var masterPassword = randomWords[i];

      for (var j = TEST_SIZE, jEnd = TEST_SIZE * 2; j < jEnd; j++) {
        var paranoidLock = randomWords[j];

        for (var k = 0, kEnd = testRealDomains.length; k < kEnd; k++) {
          var uri = testRealDomains[k];

          // generate paranoid passwords
          var paranoidPassword = paranoid.generate({
            masterPassword: masterPassword,
            paranoidLock: paranoidLock,
            uri: uri
          });

          // expect zero duplicates
          var exists = passwords.indexOf(paranoidPassword) !== -1;
          it('should be unique for every site', function () {
            expect(exists).to.equal(false);
          });

          // add to list of generated passwords
          passwords.push(paranoidPassword);
          duplicates[paranoidPassword] =
            masterPassword+':'+paranoidLock+':'+uri;

        } // end for k in testRealDomains
      } // end j in TEST_SIZE randomWords
    } // end i in TEST_SIZE randomWords
  });


  describe('#Parameters', function(){
    var master = randomWords[0];
    var lock = randomWords[1];
    var uri = testRealDomains[0];

    var withDefaults = paranoid.generate({
      masterPassword: master,
      paranoidLock: lock,
      uri: uri
    });

    it('should allow masterPassword or master', function () {
      // generate paranoid passwords
      var withMaster = paranoid.generate({
        master: master,
        paranoidLock: lock,
        uri: uri
      });

      expect(withMaster).to.equal(withDefaults);
    });

    it('should allow paranoidLock or lock', function () {
      var withLock = paranoid.generate({
        masterPassword: master,
        lock: lock,
        uri: uri
      });
      expect(withLock).to.equal(withDefaults);
    });

    it('should allow uri or target', function () {
      var withTarget = paranoid.generate({
        masterPassword: master,
        paranoidLock: lock,
        target: uri
      });
      expect(withTarget).to.equal(withDefaults);
    });

    it('should allow master and lock', function () {
      var withMasterAndLock = paranoid.generate({
        master: master,
        lock: lock,
        uri: uri
      });
      expect(withMasterAndLock).to.equal(withDefaults);
    });

    it('should allow master and lock and target', function () {
      var withMasterAndLockAndTarget = paranoid.generate({
        master: master,
        lock: lock,
        target: uri
      });
      expect(withMasterAndLockAndTarget).to.equal(withDefaults);
    });
  }); // end describe #parameters

}); // end describe Paranoid
