# PuTTY::Key #

[![Gem Version](https://badge.fury.io/rb/putty-key.svg)](http://badge.fury.io/rb/putty-key) [![Build Status](https://travis-ci.org/philr/putty-key.svg?branch=master)](https://travis-ci.org/philr/putty-key) [![Coverage Status](https://coveralls.io/repos/philr/putty-key/badge.svg?branch=master)](https://coveralls.io/r/philr/putty-key?branch=master)

PuTTY::Key contains a refinement to OpenSSL::PKey to add support for converting
OpenSSL::PKey::DSA and OpenSSL::PKey::RSA private keys to and from the PuTTY
private key (PPK) format. This allows DSA and RSA OpenSSH keys to be converted
for use with PuTTY and vice-versa.


## Installation ##

To install the PuTTY::Key gem, run the following command:

    gem install putty-key

To add PuTTY::Key as a Bundler dependency, add the following line to your
`Gemfile`:

    gem 'putty-key'


## Compatibility ##

PuTTY::Key is compatible with Ruby MRI 2.1.0+, JRuby 9.0.0.0+ and
Rubinius 2.5.4+.


## Usage ##

To use PuTTY::Key, it must first be loaded with:

    require 'putty/key'

The included refinement must can then either be activated in the lexical scope
(file, class or module) where it will be used with:

    using PuTTY::Key

or installed globally with:

    PuTTY::Key.global_install

** todo: usage guide here **


## Documentation ##

Documentation for PuTTY::Key is available on
[RubyDoc.info](http://www.rubydoc.info/gems/putty-key).


## License ##

PuTTY::Key is distributed under the terms of the MIT license. A copy of this
license can be found in the included LICENSE file.


## GitHub Project ##

Source code, release information and the issue tracker can be found on the
[PuTTY::Key GitHub project page](https://github.com/philr/putty-key).
