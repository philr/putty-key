module PuTTY
  # PuTTY::Key contains a refinement to OpenSSL::PKey to add support for
  # converting OpenSSL::PKey::DSA and OpenSSL::PKey::RSA private keys to and
  # from the PuTTY private key (PPK) format.
  module Key

    def self.global_install
      ::PuTTY::Key::OpenSSL.global_install
    end
  end
end

require 'putty/key/version'
require 'putty/key/error'
require 'putty/key/util'
require 'putty/key/ppk'
require 'putty/key/openssl'

