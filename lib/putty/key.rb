module PuTTY
  # PuTTY::Key handles reading and writing PuTTY private key (.ppk) files. It
  # includes a refinement to Ruby's OpenSSL library to add support for
  # converting DSA, EC and RSA private keys to and from PuTTY private key files.
  # This allows OpenSSH ecdsa, ssh-dss and ssh-rsa private keys to be converted
  # to and from PuTTY format.
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

require 'putty/key/version'
require 'putty/key/error'
require 'putty/key/util'
require 'putty/key/ppk'
require 'putty/key/openssl'

