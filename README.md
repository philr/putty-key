# PuTTY::Key #

[![RubyGems](https://img.shields.io/gem/v/putty-key?logo=rubygems&label=Gem)](https://rubygems.org/gems/putty-key) [![Tests](https://github.com/philr/putty-key/workflows/Tests/badge.svg?branch=master&event=push)](https://github.com/philr/putty-key/actions?query=workflow%3ATests+branch%3Amaster+event%3Apush) [![Coverage Status](https://img.shields.io/coveralls/github/philr/putty-key/master?label=Coverage&logo=Coveralls)](https://coveralls.io/github/philr/putty-key?branch=master)

PuTTY::Key is a Ruby implementation of the PuTTY private key (ppk) format
(versions 2 and 3), handling reading and writing .ppk files. It includes a
refinement to Ruby's OpenSSL library to add support for converting DSA, EC and
RSA private keys to and from PuTTY private key files. This allows OpenSSH ecdsa,
ssh-dss and ssh-rsa private keys to be converted to and from PuTTY's private key
format.


## Installation ##

To install the PuTTY::Key gem, run the following command:

```bash
gem install putty-key
```

To add PuTTY::Key as a Bundler dependency, add the following line to your
`Gemfile`:

```ruby
gem 'putty-key'
```

## Compatibility ##

PuTTY::Key is compatible with Ruby MRI 2.1.0+ and JRuby 9.1.0.0+.


## Formats ##

Format 2 and 3 .ppk files are supported. Format 1 (not supported) was only used
briefly early on in the development of the .ppk format and was never included in
a PuTTY release. Format 2 is supported by PuTTY version 0.52 onwards. Format 3
is supported by PuTTY version 0.75 onwards. By default, `PuTTY::Key::PPK` saves
files using format 2. Format 3 can be selected with the `format` parameter.

[libargon2](https://github.com/P-H-C/phc-winner-argon2) is required to load and
save encrypted format 3 files. Binaries are typically available with your OS
distribution. For Windows, binaries are available from the
[argon2-windows](https://github.com/philr/argon2-windows/releases) repository.
Use either Argon2OptDll.dll for CPUs supporting AVX or Argon2RefDll.dll
otherwise.


## Usage ##

To use PuTTY::Key, it must first be loaded with:

```ruby
require 'putty/key'
```

The included [refinement](https://ruby-doc.org/core/doc/syntax/refinements_rdoc.html)
to Ruby's OpenSSL library can then either be activated in the lexical scope
(file, class or module) where it will be used with:

```ruby
using PuTTY::Key
```

or installed globally by calling:

```ruby
PuTTY::Key.global_install
```

The following sections give examples of how PuTTY::Key can be used.


### Converting a .pem formatted key file to an unencrypted .ppk file ###

```ruby
require 'openssl'
require 'putty/key'
using PuTTY::Key    # or PuTTY::Key.global_install

pem = File.read('key.pem', mode: 'rb')
pkey = OpenSSL::PKey.read(pem)
ppk = pkey.to_ppk
ppk.comment = 'Optional comment'
ppk.save('key.ppk')
```

Use `ppk.save('key.ppk', format: 3)` to save a format 3 file instead of
format 2.


### Generating a new RSA key and saving it as an encrypted .ppk file ###

```ruby
require 'openssl'
require 'putty/key'
using PuTTY::Key    # or PuTTY::Key.global_install

rsa = OpenSSL::PKey::RSA.generate(2048)
ppk = rsa.to_ppk
ppk.comment = 'RSA 2048'
ppk.save('rsa.ppk', 'Passphrase for encryption')
```

Use `ppk.save('rsa.ppk', 'Passphrase for encryption', format: 3)` to save a
format 3 file instead of format 2.


### Converting an unencrypted .ppk file to .pem format ###

```ruby
require 'openssl'
require 'putty/key'
using PuTTY::Key    # or PuTTY::Key.global_install

ppk = PuTTY::Key::PPK.new('key.ppk')
pkey = OpenSSL::PKey.from_ppk(ppk)
pem = pkey.to_pem
File.write('key.pem', pem, mode: 'wb')
```


### Decrypting a .ppk file and re-saving it without encryption ###

```ruby
require 'putty/key'

ppk = PuTTY::Key::PPK.new('rsa.ppk', 'Passphrase for encryption')
ppk.save('rsa-plain.ppk')
```

Use `ppk.save('rsa-plain.ppk', format: 3)` to save a format 3 file instead of
format 2.


## API Documentation ##

API documentation for PuTTY::Key is available on
[RubyDoc.info](https://www.rubydoc.info/gems/putty-key).


## License ##

PuTTY::Key is distributed under the terms of the MIT license. A copy of this
license can be found in the included LICENSE file.


## GitHub Project ##

Source code, release information and the issue tracker can be found on the
[PuTTY::Key GitHub project page](https://github.com/philr/putty-key).
