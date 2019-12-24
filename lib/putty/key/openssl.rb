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

      # Add an alternative alias for nistp256 used by JRuby.
      SSH_CURVES['secp256r1'] = 'nistp256'

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
              _, p, q, g, pub_key = Util.ssh_unpack(ppk.public_blob, :string, :mpint, :mpint, :mpint, :mpint)
              priv_key = Util.ssh_unpack(ppk.private_blob, :mpint).first

              if pkey.respond_to?(:set_key)
                # :nocov_no_openssl_pkey_dsa_set_key:
                pkey.set_key(pub_key, priv_key)
                pkey.set_pqg(p, q, g)
                # :nocov_no_openssl_pkey_dsa_set_key:
              else
                # :nocov_openssl_pkey_dsa_set_key:
                pkey.p, pkey.q, pkey.g, pkey.pub_key, pkey.priv_key = p, q, g, pub_key, priv_key
                # :nocov_openssl_pkey_dsa_set_key:
              end
            end
          when 'ssh-rsa'
            ::OpenSSL::PKey::RSA.new.tap do |pkey|
              _, e, n = Util.ssh_unpack(ppk.public_blob, :string, :mpint, :mpint)
              d, p, q, iqmp = Util.ssh_unpack(ppk.private_blob, :mpint, :mpint, :mpint, :mpint)

              dmp1 = d % (p - 1)
              dmq1 = d % (q - 1)

              if pkey.respond_to?(:set_factors)
                # :nocov_no_openssl_pkey_rsa_set_factors:
                pkey.set_factors(p, q)
                pkey.set_key(n, e, d)
                pkey.set_crt_params(dmp1, dmq1, iqmp)
                # :nocov_no_openssl_pkey_rsa_set_factors:
              else
                # :nocov_openssl_pkey_rsa_set_factors:
                pkey.e, pkey.n, pkey.d, pkey.p, pkey.q, pkey.iqmp, pkey.dmp1, pkey.dmq1 = e, n, d, p, q, iqmp, dmp1, dmq1
                # :nocov_openssl_pkey_rsa_set_factors:
              end
            end
          when /\Aecdsa-sha2-(nistp(?:256|384|521))\z/
            curve = OPENSSL_CURVES[$1]

            # Old versions of jruby-openssl don't include an EC class (version 0.9.16).
            ec_class = (::OpenSSL::PKey::EC rescue raise ArgumentError, "Unsupported algorithm: #{ppk.algorithm}")

            ec_class.new(curve).tap do |pkey|
              _, _, point = Util.ssh_unpack(ppk.public_blob, :string, :string, :mpint)
              group = pkey.group || ::OpenSSL::PKey::EC::Group.new(curve)
              pkey.public_key = ::OpenSSL::PKey::EC::Point.new(group, point)
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
        #
        # @raise [InvalidStateError] If the key has not been initialized.
        def to_ppk
          PPK.new.tap do |ppk|
            ppk.algorithm = 'ssh-dss'
            begin
              ppk.public_blob = Util.ssh_pack('ssh-dss', p, q, g, pub_key)
              ppk.private_blob = Util.ssh_pack(priv_key)
            rescue NilValueError
              raise InvalidStateError, 'The key has not been fully initialized (the p, q, g, pub_key and priv_key parameters must all be assigned)'
            end
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
          curve = group && group.curve_name
          raise InvalidStateError, 'The key has not been fully initialized (a curve name must be assigned)' unless curve
          ssh_curve = SSH_CURVES[curve]
          raise UnsupportedCurveError, "The curve '#{curve}' is not supported" unless ssh_curve

          PPK.new.tap do |ppk|
            ppk.algorithm = "ecdsa-sha2-#{ssh_curve}"
            begin
              ppk.public_blob = Util.ssh_pack(ppk.algorithm, ssh_curve, public_key && public_key.to_bn)
              ppk.private_blob = Util.ssh_pack(private_key)
            rescue NilValueError
              raise InvalidStateError, 'The key has not been fully initialized (public_key and private_key must both be assigned)'
            end
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
        #
        # @raise [InvalidStateError] If the key has not been initialized.
        def to_ppk
          PPK.new.tap do |ppk|
            ppk.algorithm = 'ssh-rsa'
            begin
              ppk.public_blob = Util.ssh_pack('ssh-rsa', e, n)
              ppk.private_blob = Util.ssh_pack(d, p, q, iqmp)
            rescue NilValueError
              raise InvalidStateError, 'The key has not been fully initialized (the e, n, d, p, q and iqmp parameters must all be assigned)'
            end
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
