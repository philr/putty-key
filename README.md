# PuTTY::Key #

[![Gem Version](https://badge.fury.io/rb/putty-key.svg)](http://badge.fury.io/rb/putty-key) [![Build Status](https://travis-ci.org/philr/putty-key.svg?branch=master)](https://travis-ci.org/philr/putty-key) [![Coverage Status](https://coveralls.io/repos/philr/putty-key/badge.svg?branch=master)](https://coveralls.io/r/philr/putty-key?branch=master)

PuTTY::Key is a pure-Ruby implementation of the PuTTY private key (ppk) format,
handling reading and writing .ppk files. It includes a refinement to Ruby's
OpenSSL library to add support for converting DSA, EC and RSA private keys to
and from PuTTY private key files. This allows OpenSSH ecdsa, ssh-dss and ssh-rsa
private keys to be converted to and from PuTTY's private key format.


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

PuTTY::Key is compatible with Ruby MRI 2.1.0+ and Rubinius 2.5.4+ (provided the
OpenSSL standard library is available).

JRuby will be supported (DSA/DSS and RSA keys only) once jruby-openssl pull
requests [#82](https://github.com/jruby/jruby-openssl/pull/82) and
[#83](https://github.com/jruby/jruby-openssl/pull/83) have been released.


## Usage ##

To use PuTTY::Key, it must first be loaded with:

```ruby
require 'putty/key'
```

The included [refinement](http://ruby-doc.org/core-2.3.0/doc/syntax/refinements_rdoc.html)
to Ruby's OpenSSL library can then either be activated in the lexical scope
(file, class or module) where it will be used with:

```ruby
using PuTTY::Key
```

or installed globally by calling:

```ruby
PuTTY::Key.global_install
```

Note that Rubinius (as of version 3.22) does not support refinements, so the
global installation approach is required.

JRuby (as of version 9.0.5.0) includes support for refinements, but there are
still outstanding issues. The global installation approach is preferable on
JRuby.

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


## API Documentation ##

API documentation for PuTTY::Key is available on
[RubyDoc.info](http://www.rubydoc.info/gems/putty-key).


## License ##

PuTTY::Key is distributed under the terms of the MIT license. A copy of this
license can be found in the included LICENSE file.


## GitHub Project ##

Source code, release information and the issue tracker can be found on the
[PuTTY::Key GitHub project page](https://github.com/philr/putty-key).
