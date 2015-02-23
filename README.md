####Paranoid Password - Password generation, but better.

[ParanoidPassword.com](http://ParanoidPassword.com) - Generate Paranoid Passwords [Here](https://collingreen.github.io/paranoid).

ParanoidPassword is a password generation algorithm with some extra
features on top to make living in a digital, password-focused world easier long term.

Everyone knows they should use a different, cryptographically strong password for every site and program, but almost nobody does it because it is so inconvenient. Paranoid is a password generation algorithm that creates unique, strong passwords from a small set of remembered passwords, plus some tools to make managing those passwords much more convenient.

###How it Works
Using Paranoid requires you to remember at least two passwords - your very strong 'master passphrase', and another 'paranoid lock' (you *can and should* mix and match these to add even more security in the same way people generally have different 'levels' of passwords they only expose to more important accounts). Next, Paranoid takes the site or program to which you are logging in, hashes (sha256) it using your paranoid lock, and uses that as the salt in thousands of iterations of the [PBKDF2](http://en.wikipedia.org/wiki/PBKDF2), an industry standard password hashing algorithm. When it finishes, Paranoid spits out your 'paranoid hash', which is then used as the password for that particular site.

Now you have a strong password for that site without having to remember new passwords, and when they eventually lose your password, it won't be the same as anywhere else, even if you use the same master password and paranoid lock.

Perhaps more importantly, by generating your passwords when you need them instead of storing them in some database, you always have access to your passwords from any device, you aren't constantly transmitting them across the internet, and there is no single point of failure that results in all your passwords being lost at once.

Paranoid was created to solve the same problems addressed
by PwdHash without exposing the same vulnerabilities
(easy md5 hashes, known salt, password length leaking,
vulnerable browser plugins) and with the ability to increase
the algorithm complexity over time.

###Use It
If all you want to do is use Paranoid to make your life easier, there is an app for pretty much any device where you would need to enter a password (if you really want one that is missing, let us know!). Check the [homepage](paranoidpassword.com) or search for third party apps on your app store of choice.

If you're ready to add Paranoid support to a product, want to make Paranoid itself better, or want to inspect the source (more eyes means less bugs, or so they say), you should clone this repo `git clone https://github.com/collingreen/paranoid`. You can `require paranoid` like any npm module, use it in your browser with [browserify](http://browserify.org/), or just use the source directly. The algorithm itself is extremely simple and uses openly-available, industry-standard tools, so porting Paranoid to other languages should be extremely easy (and fantastic for the community). If you have a working port of Paranoid (with tests!), let us know and we will list it on this page.


###Tests
Uses [Mocha](http://mochajs.org/) and [Chai](http://chaijs.com/) for testing.

Run the tests with `make test` or `make test-nyan`


###What it Does
- Paranoid provides a safer way to remember a few good passwords without ever giving the same password to two different sites.
- Paranoid gives you access to your generated passwords anywhere - all you need is the app (or webpage linked at the top of this page) and your memory!

###Side Benefits
- Can help prevent you from losing your password to a phishing site (different domain means it will be a different password).
- Can help prevent you from losing your password on sites without https (your password is generated locally, so only the paranoid hash is transmitted across the internet).

###What it Doesn't Do
- Paranoid doesn't protect you from giving away your passwords via various social engineering attacks (don't tell people your passwords!).
- Paranoid doesn't protect you from people watching you type your password, malicious third-party password apps (try to use legit apps), keyloggers, compromised devices (computer, phone, router, network, etc, etc, etc), or anything similar.
- Paranoid doesn't solve anything except re-used or weak passwords - be safe on the internet.


###Why A Better Password Solution is Needed
There are three kinds of developers out there, and they are all contributing to your passwords being compromised (plus the NSA snooping all your traffic).

1. The bad guys are actively harvesting and selling your passwords from their real sites, convincing you to enter your password on various fake sites, silently breaking into good sites and making them act like bad sites, and accumulating massive lists of email/username/password combinations using compromised machines or brute forcing leaked password dumps.

1. The good intentioned but uneducated developers are creating site after site with various trivial-to-exploit security flaws, leaking [literally billions](http://www.securesafe.com/en/security-blog/1.2-billion-passwords-hacked-now-what/) of username/password combinations. This isn't just the little guys - [the worst offenders include far far too many of major household-name companies](http://www.informationisbeautiful.net/visualizations/worlds-biggest-data-breaches-hacks/).

1. Finally, the fantastic, up-to-date, vigilant developers are creating sites with good security practices, a thorough understanding of the different pieces of their networks, and a careful eye for leaking information of any kind. They are literally doing everything they can to protect your data, then promptly falling victim to the next catastrophic exploit of the month (BREACH, HeartBleed, PoodleBleed, etc, etc, etc) or having their data lost by careless/malicious/stupid employees/contracters.

**As soon as you use a password on a site, you absolutely have to treat it like it is already lost.**


###Vulnerabilities
While it is unreasonably difficult to infer your password from the paranoid hash given to a particular site, it is perfectly possible for the bad guys to guess your master passphrase and paranoid lock if they are very weak, which would allow them to generate your other paranoid hashes that use the same master and lock. *Please* use strong passwords!

###Alternatives
There are many password solutions out there (although most of them have frightening vulnerabilities or risk points). Learn how they work, decide what trade-offs are worth it for you (for example, Paranoid makes it easy and safe to have your passwords anywhere but makes it possible for attackers with your master password and the correct lock to generate your password for the relevant sites), and take your password security seriously.

###Your Own Password Page
You can (and should!) fork this repository and host the generation page (in the gh_pages branch) yourself or from your github fork so you can be absolutely sure what you are using. You can also have your own dev environment for Paranoid set up in seconds using nitrous.io by clicking the button to the right --> [![Hack paranoid on Nitrous](https://d3o0mnbgv6k92a.cloudfront.net/assets/hack-s-v1-0616054bfad452919522f1d08ad1fddf.png)](https://www.nitrous.io/hack_button?source=embed&runtime=nodejs&repo=collingreen%2Fparanoid&file_to_open=lib%2Fparanoid.js)

