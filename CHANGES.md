# Changes #

## Version 1.1.2 - 16-Oct-2024 ##

* Fix `Java::JavaLang::NullPointerException` being raised instead of
  `PuTTY::Key::InvalidStateError` by `OpenSSL::PKey::EC#to_ppk` on JRuby 9.4
  when the key is not initialized.


## Version 1.1.1 - 23-Oct-2022 ##

* Add support for Ruby 3.2.
* Add support for OpenSSL 3 (requires either Ruby 3.1+, or version 3.0.0+ of the
  openssl gem).


## Version 1.1.0 - 24-May-2021 ##

* Add support for [format 3 .ppk files](https://www.chiark.greenend.org.uk/~sgtatham/putty/wishlist/ppk3.html)
  introduced in PuTTY version 0.75. `PuTTY::Key::PPK#save` defaults to saving
  format 2 files. [libargon2](https://github.com/P-H-C/phc-winner-argon2) is
  required to load and save encrypted format 3 files.
* Write files using LF line endings (Unix) instead of CRLF (Windows) to match
  PuTTYgen version 0.75 (versions up to 0.74 used CRLF, but are compatible with
  CRLF and LF).
* Support reading files with CR line endings (Classic Mac OS).
* Support reading from and writing to `IO`-like streams.
* Allow loading and saving files with empty private or public keys.
* Fix adding unnecessary padding to the private key on saving when it is an
  exact multiple of the block size.


## Version 1.0.1 - 26-Dec-2019 ##

* Fix errors converting DSA and RSA PPK keys to OpenSSL in
  `OpenSSL::PKey.from_ppk(ppk)` with Ruby MRI 2.4 and later.
* Fix errors converting EC PPK keys to OpenSSL in
  `OpenSSL::PKey.from_ppk(ppk)` with JRuby 9.2.
* Fix errors converting EC keys from OpenSSL to PPK in
  `OpenSSL::PKey::EC.to_ppk` with JRuby 9.2.
* Enable frozen string literals.
* Load dependencies using `require_relative` instead of `require`.
* Remove support for Rubinius.


## Version 1.0.0 - 2-Apr-2016 ##

* First release.
