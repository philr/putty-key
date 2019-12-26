# Changes #

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
