# frozen_string_literal: true

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

      # Either a real JRuby NullPointerException, or a fake class that won't be
      # raised. Can be rescued to handle NullPointerException on jruby.
      JavaNullPointerException = RUBY_ENGINE == 'jruby' ? Java::JavaLang::NullPointerException : Class.new(Exception)
      private_constant :JavaNullPointerException

      # OpenSSL version helper methods.
      #
      # @private
      module Version
        class << self
          # Determines if the Ruby OpenSSL wrapper is using the OpenSSL library
          # (not LibreSSL and not JRuby) and if the version matches the required
          # version.
          #
          # @param major [Integer] The required major version. `nil` if any
          #   version of OpenSSL is sufficient.
          # @param minor [Integer] The required minor version.
          # @param fix [Integer] The required fix version.
          # @param patch [Integer] The required patch version.
          # @return [Boolean] `true` if the requirements are met, otherwise
          #   `false`.
          def openssl?(major = nil, minor = 0, fix = 0, patch = 0)
            return false if ::OpenSSL::OPENSSL_VERSION.include?('LibreSSL')
            return false if ::OpenSSL::OPENSSL_VERSION.include?('JRuby')
            return true unless major
            required_version = major * 0x10000000 + minor * 0x100000 + fix * 0x1000 + patch * 0x10
            ::OpenSSL::OPENSSL_VERSION_NUMBER >= required_version
          end
        end
      end
      private_constant :Version

      # Methods to build OpenSSL private keys from a {PPK}.
      #
      # @private
      module PKeyBuilding
        class << self
          # Creates a new OpenSSL DSA private key for the given DSA {PPK}.
          #
          # @param ppk [PPK] A DSA {PPK}.
          # @return [::OpenSSL::PKey::DSA] The OpenSSL DSA private key.
          def ppk_to_dsa(ppk)
            _, p, q, g, pub_key = Util.ssh_unpack(ppk.public_blob, :string, :mpint, :mpint, :mpint, :mpint)
            priv_key = Util.ssh_unpack(ppk.private_blob, :mpint).first
            dsa_from_params(p, q, g, pub_key, priv_key)
          end

          # Creates a new OpenSSL RSA private key for the given RSA {PPK}.
          #
          # @param ppk [PPK] An RSA {PPK}.
          # @return [::OpenSSL::PKey::RSA] The OpenSSL RSA private key.
          def ppk_to_rsa(ppk)
            _, e, n = Util.ssh_unpack(ppk.public_blob, :string, :mpint, :mpint)
            d, p, q, iqmp = Util.ssh_unpack(ppk.private_blob, :mpint, :mpint, :mpint, :mpint)
            dmp1 = d % (p - 1)
            dmq1 = d % (q - 1)
            rsa_from_params(e, n, d, p, q, iqmp, dmp1, dmq1)
          end

          # Creates a new OpenSSL EC private key for the given EC {PPK}.
          #
          # @param ppk [PPK] An EC {PPK}.
          # @param ppk_curve [String] The PPK curve name extracted from the
          #   PPK algorithm name.
          # @return [::OpenSSL::PKey::EC] The OpenSSL EC private key.
          def ppk_to_ec(ppk, ppk_curve)
            curve = OPENSSL_CURVES[ppk_curve]
            _, _, pub_key = Util.ssh_unpack(ppk.public_blob, :string, :string, :mpint)
            priv_key = Util.ssh_unpack(ppk.private_blob, :mpint).first
            ec_from_params(curve, pub_key, priv_key)
          end

          private

          if Version.openssl?(3)
            # OpenSSL v3 private keys are immutable. The Ruby OpenSSL wrapper
            # doesn't provide a method to construct private keys using the
            # parameters. Build DER (ASN.1) encoded versions of the keys.
            #
            # In theory this should be usable universally. However
            # ::OpenSSL::PKey::EC::Point#to_octet_string is only supported from
            # Ruby >= 2.4 and there are issues with JRuby's OpenSSL library
            # (that doesn't make use of OpenSSL).

            # :nocov_no_openssl3:

            # Creates a new OpenSSL DSA private key with the given parameters.
            #
            # @param p [::OpenSSL::BN] The p parameter (prime).
            # @param q [::OpenSSL::BN] The q parameter (prime).
            # @param g [::OpenSSL::BN] The g parameter.
            # @param pub_key [::OpenSSL::BN] The public key.
            # @param priv_key [::OpenSSL::BN] The private key.
            # @return [::OpenSSL::PKey::DSA] The OpenSSL DSA private key.
            def dsa_from_params(p, q, g, pub_key, priv_key)
              # https://www.openssl.org/docs/man3.0/man1/openssl-dsa.html (outform parameter).
              sequence = [
                ::OpenSSL::ASN1::Integer.new(0),
                ::OpenSSL::ASN1::Integer.new(p),
                ::OpenSSL::ASN1::Integer.new(q),
                ::OpenSSL::ASN1::Integer.new(g),
                ::OpenSSL::ASN1::Integer.new(pub_key),
                ::OpenSSL::ASN1::Integer.new(priv_key)
              ]

              ::OpenSSL::PKey::DSA.new(::OpenSSL::ASN1::Sequence.new(sequence).to_der)
            end

            # Creates a new OpenSSL RSA private key with the given parameters.
            #
            # @param e [::OpenSSL::BN] The public key exponent.
            # @param n [::OpenSSL::BN] The modulus.
            # @param d [::OpenSSL::BN] The private key exponent.
            # @param p [::OpenSSL::BN] The p prime.
            # @param q [::OpenSSL::BN] The q prime.
            # @param iqmp [::OpenSSL::BN] The inverse of q, mod p.
            # @param dmp1 [::OpenSSL::BN] `d` mod (`p` - 1).
            # @param dmq1 [::OpenSSL::BN] `d` mod (`q` - 1).
            # @return [::OpenSSL::PKey::RSA] The OpenSSL RSA private key.
            def rsa_from_params(e, n, d, p, q, iqmp, dmp1, dmq1)
              # RFC 3447 Appendix A.1.2
              sequence = [
                ::OpenSSL::ASN1::Integer.new(0),
                ::OpenSSL::ASN1::Integer.new(n),
                ::OpenSSL::ASN1::Integer.new(e),
                ::OpenSSL::ASN1::Integer.new(d),
                ::OpenSSL::ASN1::Integer.new(p),
                ::OpenSSL::ASN1::Integer.new(q),
                ::OpenSSL::ASN1::Integer.new(dmp1),
                ::OpenSSL::ASN1::Integer.new(dmq1),
                ::OpenSSL::ASN1::Integer.new(iqmp)
              ]

              ::OpenSSL::PKey::RSA.new(::OpenSSL::ASN1::Sequence.new(sequence).to_der)
            end

            # Creates a new OpenSSL EC private key with the given parameters.
            #
            # @param curve [String] The name of the OpenSSL EC curve.
            # @param pub_key [::OpenSSL::BN] The public key.
            # @param priv_key [::OpenSSL::BN] The private key.
            # @return [::OpenSSL::PKey::EC] The OpenSSL EC private key.
            def ec_from_params(curve, pub_key, priv_key)
              group = ::OpenSSL::PKey::EC::Group.new(curve)
              point = ::OpenSSL::PKey::EC::Point.new(group, pub_key)
              point_string = point.to_octet_string(:uncompressed)

              # RFC 5915 Section 3
              sequence = [
                ::OpenSSL::ASN1::Integer.new(1),
                ::OpenSSL::ASN1::OctetString.new(priv_key.to_s(2)),
                ::OpenSSL::ASN1::ObjectId.new(curve, 0, :EXPLICIT),
                ::OpenSSL::ASN1::BitString.new(point_string, 1, :EXPLICIT)
              ]

              ::OpenSSL::PKey::EC.new(::OpenSSL::ASN1::Sequence.new(sequence).to_der)
            end
            # :nocov_no_openssl3:
          else
            # :nocov_openssl3:
            if ::OpenSSL::PKey::DSA.new.respond_to?(:set_key)
              # :nocov_no_openssl_pkey_dsa_set_key:

              # Creates a new OpenSSL DSA private key with the given parameters.
              #
              # @param p [::OpenSSL::BN] The p parameter.
              # @param q [::OpenSSL::BN] The q parameter.
              # @param g [::OpenSSL::BN] The g parameter.
              # @param pub_key [::OpenSSL::BN] The public key.
              # @param priv_key [::OpenSSL::BN] The private key.
              # @return [::OpenSSL::PKey::DSA] The OpenSSL DSA private key.
              def dsa_from_params(p, q, g, pub_key, priv_key)
                ::OpenSSL::PKey::DSA.new.tap do |pkey|
                  pkey.set_key(pub_key, priv_key)
                  pkey.set_pqg(p, q, g)
                end
              end
              # :nocov_no_openssl_pkey_dsa_set_key:
            else
              # :nocov_openssl_pkey_dsa_set_key:
              # Creates a new OpenSSL DSA private key with the given parameters.
              #
              # @param p [::OpenSSL::BN] The p parameter.
              # @param q [::OpenSSL::BN] The q parameter.
              # @param g [::OpenSSL::BN] The g parameter.
              # @param pub_key [::OpenSSL::BN] The public key.
              # @param priv_key [::OpenSSL::BN] The private key.
              # @return [::OpenSSL::PKey::DSA] The OpenSSL DSA private key.
              def dsa_from_params(p, q, g, pub_key, priv_key)
                ::OpenSSL::PKey::DSA.new.tap do |pkey|
                  pkey.p, pkey.q, pkey.g, pkey.pub_key, pkey.priv_key = p, q, g, pub_key, priv_key
                end
              end
              # :nocov_openssl_pkey_dsa_set_key:
            end

            if ::OpenSSL::PKey::RSA.new.respond_to?(:set_factors)
              # :nocov_no_openssl_pkey_rsa_set_factors:

              # Creates a new OpenSSL RSA private key with the given parameters.
              #
              # @param e [::OpenSSL::BN] The public key exponent.
              # @param n [::OpenSSL::BN] The modulus.
              # @param d [::OpenSSL::BN] The private key exponent.
              # @param p [::OpenSSL::BN] The p prime.
              # @param q [::OpenSSL::BN] The q prime.
              # @param iqmp [::OpenSSL::BN] The inverse of q, mod p.
              # @param dmp1 [::OpenSSL::BN] `d` mod (`p` - 1).
              # @param dmq1 [::OpenSSL::BN] `d` mod (`q` - 1).
              # @return [::OpenSSL::PKey::RSA] The OpenSSL RSA private key.
              def rsa_from_params(e, n, d, p, q, iqmp, dmp1, dmq1)
                ::OpenSSL::PKey::RSA.new.tap do |pkey|
                  pkey.set_factors(p, q)
                  pkey.set_key(n, e, d)
                  pkey.set_crt_params(dmp1, dmq1, iqmp)
                end
              end
              # :nocov_no_openssl_pkey_rsa_set_factors:
            else
              # :nocov_openssl_pkey_rsa_set_factors:

              # Creates a new OpenSSL RSA private key with the given parameters.
              #
              # @param e [::OpenSSL::BN] The public key exponent.
              # @param n [::OpenSSL::BN] The modulus.
              # @param d [::OpenSSL::BN] The private key exponent.
              # @param p [::OpenSSL::BN] The p prime.
              # @param q [::OpenSSL::BN] The q prime.
              # @param iqmp [::OpenSSL::BN] The inverse of q, mod p.
              # @param dmp1 [::OpenSSL::BN] `d` mod (`p` - 1).
              # @param dmq1 [::OpenSSL::BN] `d` mod (`q` - 1).
              # @return [::OpenSSL::PKey::RSA] The OpenSSL RSA private key.
              def rsa_from_params(e, n, d, p, q, iqmp, dmp1, dmq1)
                ::OpenSSL::PKey::RSA.new.tap do |pkey|
                  pkey.e, pkey.n, pkey.d, pkey.p, pkey.q, pkey.iqmp, pkey.dmp1, pkey.dmq1 = e, n, d, p, q, iqmp, dmp1, dmq1
                end
              end
              # :nocov_openssl_pkey_rsa_set_factors:
            end

            # Creates a new OpenSSL EC private key with the given parameters.
            #
            # @param curve [String] The name of the OpenSSL EC curve.
            # @param pub_key [::OpenSSL::BN] The public key.
            # @param priv_key [::OpenSSL::BN] The private key.
            # @return [::OpenSSL::PKey::EC] The OpenSSL EC private key.
            def ec_from_params(curve, pub_key, priv_key)
              # Old versions of jruby-openssl don't include an EC class (version 0.9.16).
              ec_class = (::OpenSSL::PKey::EC rescue raise ArgumentError, "Unsupported algorithm: #{ppk.algorithm}")

              ec_class.new(curve).tap do |pkey|
                group = pkey.group || ::OpenSSL::PKey::EC::Group.new(curve)
                pkey.public_key = ::OpenSSL::PKey::EC::Point.new(group, pub_key)
                pkey.private_key = priv_key
              end
            end
            # :nocov_openssl3:
          end
        end
      end
      private_constant :PKeyBuilding

      # The {ClassMethods} module is used to extend `OpenSSL::PKey` when
      # using the PuTTY::Key refinement or calling {PuTTY::Key.global_install}.
      # This adds a `from_ppk` class method to `OpenSSL::PKey`.
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
            PKeyBuilding.ppk_to_dsa(ppk)
          when 'ssh-rsa'
            PKeyBuilding.ppk_to_rsa(ppk)
          when /\Aecdsa-sha2-(nistp(?:256|384|521))\z/
            PKeyBuilding.ppk_to_ec(ppk, $1)
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
          g = group
          curve = g && begin
            g.curve_name
          rescue JavaNullPointerException
            nil
          end
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
      mod = OpenSSL.const_get(name)
      refine openssl_class do
        if defined?(::Refinement) && kind_of?(::Refinement)
          # :nocov_no_refinement_class:
          import_methods(mod)
          # :nocov_no_refinement_class:
        else
          # :nocov_refinement_class:
          include mod
          # :nocov_refinement_class:
        end
      end if respond_to?(:refine, true)
    end

    refine ::OpenSSL::PKey.singleton_class do
      if defined?(::Refinement) && kind_of?(::Refinement)
        # :nocov_no_refinement_class:
        import_methods(OpenSSL::ClassMethods)
        # :nocov_no_refinement_class:
      else
        # :nocov_refinement_class:
        include OpenSSL::ClassMethods
        # :nocov_refinement_class:
      end
    end if respond_to?(:refine, true)
  end
end
