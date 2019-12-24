# frozen_string_literal: true

module PuTTY
  # PuTTY::Key is a pure-Ruby implementation of the PuTTY private key (ppk)
  # format, handling reading and writing .ppk files. It includes a refinement to
  # Ruby's OpenSSL library to add support for converting DSA, EC and RSA private
  # keys to and from PuTTY private key files. This allows OpenSSH ecdsa, ssh-dss
  # and ssh-rsa private keys to be converted to and from PuTTY's private key
  # format.
  module Key

    # Makes the refinements available in PuTTY::Key available globally. After
    # calling {global_install}, it is no longer necessary to include
    # `using PuTTY::Key` when using the `to_ppk` and `from_ppk` methods added to
    # `OpenSSL::PKey`.
    def self.global_install
      ::PuTTY::Key::OpenSSL.global_install
    end
  end
end

require_relative 'key/version'
require_relative 'key/error'
require_relative 'key/util'
require_relative 'key/ppk'
require_relative 'key/openssl'

