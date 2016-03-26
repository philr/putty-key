require 'openssl'

module PuTTY
  module Key
    module OpenSSL
      # {OpenSSL::PKey} classes to be refined.
      PKEY_CLASSES = Hash[%i(DSA EC RSA).map {|c| [c, ::OpenSSL::PKey.const_get(c)] rescue nil }.compact]
      private_constant :PKEY_CLASSES

      # Mapping from SSH curve names to their equivalent OpenSSL names.
      OPENSSL_CURVES = {
        'nistp256' => 'prime256v1',
        'nistp384' => 'secp384r1',
        'nistp521' => 'secp521r1'
      }
      private_constant :OPENSSL_CURVES

      # Mapping from OpenSSL curve names to their equivalent SSH names.
      SSH_CURVES = OPENSSL_CURVES.invert
      private_constant :SSH_CURVES

      # The {ClassMethods} module is used to extend `OpenSSL::PKey` when
      # using the PuTTY::Key refinement or calling {PuTTY::Key.global_install}.
      # This adds a `from_ppk` class method to `OpenSSL::PKey`.
      #
      module ClassMethods
        # Creates a new `OpenSSL::PKey` from a PuTTY private key (instance of
        # {PPK}).
        #
        # This method is called using `OpenSSL::PKey.from_ppk(ppk)`.
        #
        # PuTTY keys using the algorithms `ssh-dss`, `ssh-rsa`,
        # `ecdsa-sha2-nistp256`, `ecdsa-sha2-nistp384` and `ecdsa-sha2-nistp521`
        # are supported.
        #
        # @return [Object] An instance of either `OpenSSL::PKey::DSA`,
        #   `OpenSSL::PKey::RSA` or `OpenSSL::PKey::EC` depending on the
        #   algorithm of `ppk`.
        #
        # @raise [ArgumentError] If `ppk` is `nil`.
        # @raise [ArgumentError] If the algorithm of `ppk` is not supported.
        def from_ppk(ppk)
          raise ArgumentError, 'ppk must not be nil' unless ppk

          case ppk.algorithm
          when 'ssh-dss'
            ::OpenSSL::PKey::DSA.new.tap do |pkey|
              _, pkey.p, pkey.q, pkey.g, pkey.pub_key = Util.ssh_unpack(ppk.public_blob, :string, :mpint, :mpint, :mpint, :mpint)
              pkey.priv_key = Util.ssh_unpack(ppk.private_blob, :mpint).first
            end
          when 'ssh-rsa'
            ::OpenSSL::PKey::RSA.new.tap do |pkey|
              _, pkey.e, pkey.n = Util.ssh_unpack(ppk.public_blob, :string, :mpint, :mpint)
              pkey.d, pkey.p, pkey.q, pkey.iqmp = Util.ssh_unpack(ppk.private_blob, :mpint, :mpint, :mpint, :mpint)
              pkey.dmp1 = pkey.d % (pkey.p - 1)
              pkey.dmq1 = pkey.d % (pkey.q - 1)
            end
          when /\Aecdsa-sha2-(nistp(?:256|384|521))\z/
            curve = OPENSSL_CURVES[$1]

            # jruby-openssl doesn't include an EC class (version 0.9.16)
            ec_class = (::OpenSSL::PKey::EC rescue raise ArgumentError, "Unsupported algorithm: #{ppk.algorithm}")

            ec_class.new(curve).tap do |pkey|
              _, _, point = Util.ssh_unpack(ppk.public_blob, :string, :string, :mpint)
              pkey.public_key = ::OpenSSL::PKey::EC::Point.new(pkey.group, point)
              pkey.private_key = Util.ssh_unpack(ppk.private_blob, :mpint).first
            end
          else
            raise ArgumentError, "Unsupported algorithm: #{ppk.algorithm}"
          end
        end
      end

      # The {DSA} module is included into `OpenSSL::PKey::DSA` when using the
      # PuTTY::Key refinement or calling {PuTTY::Key.global_install}. This adds
      # a `to_ppk` instance method to `OpenSSL::PKey::DSA`.
      module DSA
        # Returns a new {PPK} instance that is equivalent to this key.
        #
        # `to_ppk` can be called on instances of `OpenSSL::PKey::DSA`.
        #
        # @return [PPK] A new instance of {PPK} that is equivalent to this key.
        def to_ppk
          PPK.new.tap do |ppk|
            ppk.algorithm = 'ssh-dss'
            ppk.public_blob = Util.ssh_pack('ssh-dss', p, q, g, pub_key)
            ppk.private_blob = Util.ssh_pack(priv_key)
          end
        end
      end

      # The {EC} module is included into `OpenSSL::PKey::EC` when using the
      # PuTTY::Key refinement or calling {PuTTY::Key.global_install}. This adds
      # a `to_ppk` instance method to `OpenSSL::PKey::EC`.
      module EC
        # Returns a new {PPK} instance that is equivalent to this key.
        #
        # `to_ppk` can be called on instances of `OpenSSL::PKey::EC`.
        #
        # @return [PPK] A new instance of {PPK} that is equivalent to this key.
        #
        # @raise [InvalidStateError] If the key has not been initialized.
        # @raise [UnsupportedCurveError] If the key uses a curve that is not
        #   supported by PuTTY.
        def to_ppk
          raise InvalidStateError, 'The key has not been initialized (group is nil)' unless public_key
          ssh_curve = SSH_CURVES[group.curve_name]
          raise UnsupportedCurveError, "The curve '#{group.curve_name}' is not supported" unless ssh_curve

          PPK.new.tap do |ppk|
            ppk.algorithm = "ecdsa-sha2-#{ssh_curve}"
            ppk.public_blob = Util.ssh_pack(ppk.algorithm, ssh_curve, public_key.to_bn)
            ppk.private_blob = Util.ssh_pack(private_key)
          end
        end
      end

      # The {RSA} module is included into `OpenSSL::PKey::RSA` when using the
      # PuTTY::Key refinement or calling {PuTTY::Key.global_install}. This adds
      # a `to_ppk` instance method to `OpenSSL::PKey::RSA`.
      module RSA
        # Returns a new {PPK} instance that is equivalent to this key.
        #
        # `to_ppk` can be called on instances of `OpenSSL::PKey::DSA`.
        #
        # @return [PPK] A new instance of {PPK} that is equivalent to this key.
        def to_ppk
          PPK.new.tap do |ppk|
            ppk.algorithm = 'ssh-rsa'
            ppk.public_blob = Util.ssh_pack('ssh-rsa', e, n)
            ppk.private_blob = Util.ssh_pack(d, p, q, iqmp)
          end
        end
      end

      # Makes the refinements to `OpenSSL` available in PuTTY::Key available
      # globally. After calling {global_install}, it is no longer necessary to
      # include `using PuTTY::Key` when using the `to_ppk` and `from_ppk`
      # methods added to `OpenSSL::PKey`.
      def self.global_install
        PKEY_CLASSES.each do |name, openssl_class|
          mod = const_get(name)
          openssl_class.class_eval do
            include mod
          end
        end

        ::OpenSSL::PKey.module_eval do
          extend ClassMethods
        end
      end
    end

    OpenSSL.const_get(:PKEY_CLASSES).each do |name, openssl_class|
      refine openssl_class do
        include OpenSSL.const_get(name)
      end if respond_to?(:refine, true)
    end

    refine ::OpenSSL::PKey.singleton_class do
      include OpenSSL::ClassMethods
    end if respond_to?(:refine, true)
  end
end
