/*
    ParanoidPassword
    paranoidpassword.com
    github.com/collingreen/paranoid

    Collin Green

    ParanoidPassword was created to solve the same problems addressed
    by PwdHash without exposing the same vulnerabilities
    (easy md5 hashes, known salt, password length leaking,
    vulnerable browser plugins) and with the ability to increase
    the algorithm complexity over time.

    Version 1.0.0-beta
*/

var URIjs = require('URIjs');
var sjcl = require('sjcl');

var DEFAULT_ITERATIONS = 10000;


/**
 * Wrapper around the paranoid password generator that normalizes
 * the uri input, adjusts the password to fit common password requirements,
 * and provides some light convenience options.
 *
 * Accepts an object with the following fields:
 * - masterPassword, master: the master password used for generation
 * - paranoidLock, lock: the lock used to hash the uri
 * - uri, target: the target domain or program name for which the password
 *   is being generated
 * - iterations: (optional, default 10000) number of pbkdf2 iterations
 *
 * - doNotNormalizePrefix: (optional, default undefined) if set, any uri that
 *   starts with the doNotNormalizePrefix will not be normalized
 * - applyPasswordRules: (optional, default true) ensures at least one
 *   lowercase, uppercase, and numeric character
 * - removeWordBreaks: (optional, default true) remove non alphanumeric
 *   characters (makes it easy to copy and paste the entire passworda at once)
 *
 * Returns the final password on success, undefined on error.
 */
function paranoid (opts) {
  opts = opts || {};

  var masterPassword = opts.masterPassword || opts.master;
  var paranoidLock = opts.paranoidLock || opts.lock;
  var uri = opts.uri || opts.target;
  var iterations = opts.iterations || DEFAULT_ITERATIONS;

  // verify required fields are present
  if (!masterPassword || !paranoidLock || !uri) {
    return void 0;
  }

  var settings = {
    // apply password rules unless told not to
    applyPasswordRules: opts.applyPasswordRules || true,

    // remove word breaks unless told not to
    removeWordBreaks: opts.removeWordBreaks || true,

    // normalize unless prefix is given and matches the uri
    normalize: !(opts.doNotNormalizePrefix &&
          uri.substr(0, opts.doNotNormalizePrefix.length) ===
            opts.doNotNoramlizePrefix)
  };

  // normalize target if necessary
  var target = settings.normalize ? getPasswordTarget(uri) : uri;

  // generate password
  var password = generate({
    masterPassword: masterPassword,
    paranoidLock: paranoidLock,
    uri: target,
    iterations: iterations
  });

  // check for success
  if (!password) {
    return password;
  }

  // extra processing to ensure hashed password has at least one
  // lowercase, uppercase, and numeric character without being
  // extremely obvious (it is still easy to determine if you take a moment)
  if (settings.applyPasswordRules) {
    password = applyPasswordRules(password);
  }

  // remove 'word break' characters
  if (settings.removeWordBreaks) {
    password = password.replace(/[^a-zA-Z0-9]/g, '');
  }

  return password;
};

/**
 * Generate a paranoid password from the given master password,
 * paranoid lock, and uri/target. Creates a hexidecimal salt
 * using the paranoid lock an the parsed uri, then runs the master
 * password and the salt through many iterations of pbkdf2 to produce
 * an unreversable hash.
 *
 * The iterations of pbkdf2 can be increased to scale with improved
 * computing power so generating the passwords is always relatively
 * expensive computationally.
 *
 * Accepts one opts object with the following fields:
 * - masterPassword, master: the master password used for generation
 * - paranoidLock, lock: the lock used to hash the uri
 * - uri, target: the target domain or program name for which the password
 *   is being generated
 * - iterations: (optional, default 10000) number of pbkdf2 iterations
 *
 * Returns the password on success.
 * Returns undefined if missing required fields.
 */
function generate (opts) {
  opts = opts || {};

  var masterPassword = opts.masterPassword || opts.master;
  var paranoidLock = opts.paranoidLock || opts.lock;
  var uri = opts.uri || opts.target;
  var iterations = opts.iterations || DEFAULT_ITERATIONS;

  // verify required fields are present
  if (!masterPassword || !paranoidLock || !uri) {
    return void 0;
  }

  // hash lock and target into a usable salt (hex)
  var sjclSalt = sjcl.hash.sha256.hash(paranoidLock + '::' + uri);

  // run through many iterations of pbkdf2
  var hashedPasswordBits = sjcl.misc.pbkdf2(
    masterPassword, sjclSalt, iterations, 256
  );
  return sjcl.codec.base64.fromBits(hashedPasswordBits);
}; // end function generate

/**
 * Accepts a wild range of input as the password destination
 * and tries to parse it into a consistent domain or program
 * name.
 *
 * For example:
 * example.com, example.com:xx, example.com/some/page?query=yeah,
 * http://example.com, http://subdomain.example.com,
 * subdomain.example.com, user@example.com, http://user@example.com,
 * http://user:password@example.com, etc
 *
 * should all resolve to just example.com (while also supporting
 * program names, custom words/phrases, and ip addresses.
 */
function getPasswordTarget (input) {
  // remove extra whitespace
  input = input.trim();

  // lowercase everything
  input = input.toLowerCase();

  // allow ip addresses through
  var parsed = URIjs(input);
  if (parsed.is("ip")) {
    return parsed.hostname();
  } else if (isIP6Address(input) || isIP4Address(input)) {
    // TODO: should normalize these
    return input;
  };

  // special case code for 'relative' paths (not clearly a url)
  if (!parsed.is('domain')) {

    // extremely poor guess at being a domain
    if (mightBeDomain(input)) {
      // strip user/user:pass from the front
      input = stripUserPassFromFront(input);

      // try again with a fake protocol on the front
      // (is this a good idea?)
      var retryInput = 'http://' + input;
      var retry = URIjs(retryInput);
      if (retry.is('domain') && retry.domain()) {
        return retry.domain();
      } else if (parsed.pathname()) {
        return parsed.pathname();
      }
    }
    return input;
  }

  // strip user/user:pass from the front
  input = stripUserPassFromFront(input);

  return getBaseDomain(input);
};

/**
 * Lightly determine if this looks like a valid domain
 * some characters then at least one '.x'
 * this is super naive and misses a LOT of things.
 *
 * Should be replaced with a library when a good one
 * can be found.
 */
function mightBeDomain(input) {

  // ip if entirely numbers with colon or period separators
  // -- misses ip/path/to/file and scheme://ip
  if (/^(\d*[:\.])+$/.test(input)) {
    return false;
  }

  return /\w+(\.[a-zA-Z0-9]+)+/.test(input);
}

/*
 * strip user/user:pass from the front -- fully qualified uris will get
 * correctly parsed by URIjs, so we just need to cover the manually
 * entered cases (manually entered, but unintended? -- seems unlikely).
 */
function stripUserPassFromFront (input) {
  return input.replace(/^\w+(:\w+)?@/, '');
};

function getBaseDomain (uri) {

  // pre-process a bit to try to help URIjs get the right answers
  // strip anything after a # or ?
  uri = uri.replace(/#.*$/, '');
  uri = uri.replace(/\?.*$/, '');

  // strip port numbers from the very end -- not very catch-all
  if (uri.match(/\.\w+:\d+/)) {
    uri = uri.replace(/:\d+\/?$/, '');
  }

  // parse with URIjs
  var parsed = URIjs(uri);
  var result = uri;

  // if appears to be a normal domain
  if (parsed.is("domain")) {
    result = parsed.domain();
  }

  // strip / off the end
  result = result.replace(/\/+$/, '');
  return result;
}

function isIP4Address (input) {
  // from http://stackoverflow.com/a/9209720/1279574 and http://jsfiddle.net/AJEzQ/
  var ip4_test = /^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$/;
  return ip4_test.test(input);
} // end isIP4Address

function isIP6Address (input) {
  // from http://stackoverflow.com/a/9209720/1279574 and http://jsfiddle.net/AJEzQ/
  ip6_test = /^\s*((([0-9A-Fa-f]{1,4}:){7}([0-9A-Fa-f]{1,4}|:))|(([0-9A-Fa-f]{1,4}:){6}(:[0-9A-Fa-f]{1,4}|((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){5}(((:[0-9A-Fa-f]{1,4}){1,2})|:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){4}(((:[0-9A-Fa-f]{1,4}){1,3})|((:[0-9A-Fa-f]{1,4})?:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){3}(((:[0-9A-Fa-f]{1,4}){1,4})|((:[0-9A-Fa-f]{1,4}){0,2}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){2}(((:[0-9A-Fa-f]{1,4}){1,5})|((:[0-9A-Fa-f]{1,4}){0,3}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){1}(((:[0-9A-Fa-f]{1,4}){1,6})|((:[0-9A-Fa-f]{1,4}){0,4}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(:(((:[0-9A-Fa-f]{1,4}){1,7})|((:[0-9A-Fa-f]{1,4}){0,5}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:)))(%.+)?\s*$/;
  return ip6_test.test(input);
} // end isIP6Address

function applyPasswordRules (hashed_password) {
  // split into lower, upper, and numeric
  var lower = [];
  var upper = [];
  var numeric = [];
  var hashed_password = hashed_password.split('');

  for (var i = 0; i < hashed_password.length; i++) {
    var letter = hashed_password[i];
    var code = hashed_password[i].charCodeAt(0);

    // lowercase  a = 97, z = 122
    if (code >= 97 && code <= 122) {
      lower.push(letter);
    }
    // uppercase A = 65, Z = 90
    else if (code >= 65 && code <= 90) {
      upper.push(letter);
    }
    // numeric -- '0' = 48, '9' = 57
    else if (code >= 48 && code <= 57) {
      numeric.push(letter);
    }
  } // end for i in hashed_password.length

  // if no lowercase letters in hash
  if (lower.length === 0) {
    // if uppercase available for change
    if (upper.length > 1) {
      // swap one to lowercase
      var swap_index = upper.length % (numeric.length || 1);
      var swap_target = upper[swap_index];

      // find first instance of target letter in the full hash
      var target_index = hashed_password.indexOf(swap_target);

      // flip it -- lowercase is 32 character code points from uppercase
      var replacement =
        String.fromCharCode(swap_target.charCodeAt(0) + 32);
      hashed_password[target_index] = replacement;

      // remove from upper and add to lower
      upper.splice(swap_index, 1);
      lower.push(replacement);

    } // end if more than one uppercase letter

    // no extra uppercase either...
    else {
      // swap the first number from the hash
      var swap_index = 0;
      var swap_target = numeric[swap_index];

      // find the first occurance in the actual password
      var target_index = hashed_password.indexOf(swap_target);

      // switch with equivalent letter -- lowercase is 49 code points from the numbers
      var replacement =
        String.fromCharCode(swap_target.charCodeAt(0) + 49);
      hashed_password[target_index] = replacement;

      // remove from numeric and add to lower
      numeric.splice(swap_index, 1);
      lower.push(replacement);
    } // end else - no lowercase and no extra uppercase

  } // end if no lowercase letters in hash

  // if no uppercase letters in hash
  if (upper.length === 0) {
    // if lowercase available for change
    if (lower.length > 1) {
      // swap one to uppercase
      var swap_index = lower.length % (numeric.length || 1);
      var swap_target = lower[swap_index];

      // find first instance of target letter in the full hash
      var target_index = hashed_password.indexOf(swap_target);

      // flip it -- lowercase is 32 character code points from uppercase
      var replacement =
        String.fromCharCode(swap_target.charCodeAt(0) - 32);
      hashed_password[target_index] = replacement;

      // remove from lower and add to upper
      lower.splice(swap_index, 1);
      upper.push(replacement);
    } // end if more than one lowercase letter

    // no extra lowercase either...
    else {
      // swap the first number from the hash
      var swap_index = 0;
      var swap_target = numeric[swap_index];

      // find the first occurance in the actual password
      var target_index = hashed_password.indexOf(swap_target);

      // switch with equivalent letter -- uppercase is 17 code points from the numbers
      var replacement =
        String.fromCharCode(swap_target.charCodeAt(0) + 17);
      hashed_password[target_index] = replacement;

      // remove from numeric and add to upper
      numeric.splice(swap_index, 1);
      upper.push(replacement);
    } // end else - no uppercase and no extra lowercase
  } // end if no uppercase letters in hash

  // if no numbers in hash change a letter
  if (numeric.length === 0) {
    // if more lowercase than uppercase
    if (lower.length > upper.length) {
      // swap a letter with a number
      var index = lower.length % (upper.length || 1);
      var swap_target = lower[index];

      // remove from lower
      lower.splice(index, 1);
    } // end if lower.length > upper.length
    else
    {
      // swap a letter with a number
      var index = upper.length % (lower.length || 1);
      var swap_target = upper[index];

      // remove from upper
      upper.splice(index, 1);
    } // end else // lower.length <= upper.length

    // find the first occurance in the actual password
    var target_index = hashed_password.indexOf(swap_target);

    // switch with equivalent number
    var new_number = ''+swap_target.charCodeAt(0) % 10;
    hashed_password[target_index] = new_number;

    // add to numeric
    numeric.push(new_number);
  } // end if numeric.length == 0

  if (upper.length > 0 && lower.length > 0 && numeric.length > 0) {
    return hashed_password.join('');
  }

  // try again
  return applyPasswordRules(hashed_password.join(''));

} // end function applyPasswordRules


// export the public functions
exports.paranoid = paranoid;
exports.generate = generate;
exports.getPasswordTarget = getPasswordTarget;
