var expect = require('chai').expect;
var paranoid = require('../lib/paranoid.js');

// get getPasswordTarget function from paranoid
var getPasswordTarget = paranoid.getPasswordTarget;

var testData = require('./testData');
var testDomains = testData.testDomains;
var testUris = testData.testUris;
var testIPs = testData.testIPs;
var testManualInputs = testData.testManualInputs;

describe('Paranoid.getPasswordTarget', function () {
  for (var i = 0; i < testDomains.length; i++) {
    describe('#DomainParsing - ', function () {
      var raw = testDomains[i][0];
      var target = testDomains[i][1];
      it(raw + ' -> ' + target, function () {
        var base = getPasswordTarget(raw);
        expect(
          base,
          raw + " -> " + target
        ).to.equal(target);
      });
    });
  }

  for (var i = 0; i < testManualInputs.length; i++) {
    describe('#ManualInput - ', function () {
      var raw = testManualInputs[i][0];
      var target = testManualInputs[i][1];
      it(raw + ' -> ' + target, function () {
        var base = getPasswordTarget(raw);
        expect(
          base,
          raw + " -> " + target
        ).to.equal(target);
      });
    });
  }

  for (var i = 0; i < testIPs.length; i++) {
    describe('#IPs - ', function () {
      var raw = testIPs[i][0];
      var target = testIPs[i][1];
      it(raw + ' -> ' + target, function () {
        var base = getPasswordTarget(raw);
        expect(
          base,
          raw + " -> " + target
        ).to.equal(target);
      });
    });
  }
});
