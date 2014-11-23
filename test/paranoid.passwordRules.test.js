var expect = require('chai').expect;
var rewire = require('rewire');
var paranoid = rewire('../lib/paranoid.js');


var lower_upper_numeric_tests = [
    'aaaaaaaaaaaaaaaaaaaaaaaaaa', // no upper or numeric
    '12345678912345678912345678', // no upper or lower
    'ABCDEFGHIJKLMNOPQRSTUVWXYZ', // no lower or numeric
    'AbCd1209843295137853218751', // already looks good
    'A1234123412341234123412341', // not enough uppercase to switch to lower
    'a1234123412341234123412341', // not enough lowercase to switch to upper
];

// get password rules function from paranoid
var applyPasswordRules = paranoid.__get__("applyPasswordRules");

describe('Paranoid', function(){
  describe('#applyPasswordRules', function(){

    for (var i = 0; i < lower_upper_numeric_tests.length; i++) {
      var password_test = applyPasswordRules(lower_upper_numeric_tests[i]);

      it('should always have at least one lowercase character', function () {
        expect(password_test.match(/[a-z]/)).to.not.equal(null);
      });

      it('should always have at least one uppercase character', function () {
        expect(password_test.match(/[A-Z]/)).to.not.equal(null);
      });

      it('should always have at least one numeric character', function () {
        expect(password_test.match(/[0-9]/)).to.not.equal(null);
      });
    }
  })
});
