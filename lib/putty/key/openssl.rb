require 'openssl'

module PuTTY
  module Key
    module OpenSSL
      PKEY_CLASSES = Hash[%i(DSA EC RSA).map {|c| [c, ::OpenSSL::PKey.const_get(c)] rescue nil }.compact]

      OPENSSL_CURVES = {
        'nistp256' => 'prime256v1',
        'nistp384' => 'secp384r1',
        'nistp521' => 'secp521r1'
      }

      SSH_CURVES = OPENSSL_CURVES.invert

      module ClassMethods
        def from_ppk(ppk)
          raise ArgumentError, 'ppk must not be nil' unless ppk

          case ppk.algorithm
          when 'ssh-dss'
            ::OpenSSL::PKey::DSA.new.tap do |pkey|
              _, pkey.p, pkey.q, pkey.g, pkey.pub_key = Util.ssh_unpack(ppk.public_blob, :string, :mpint, :mpint, :mpint, :mpint)
              private_key = Util.ssh_unpack(ppk.private_blob, :mpint).first

              # jruby-openssl doesn't have an OpenSSL::PKey::DSA#priv_key= method (version 0.9.16)
              (pkey.priv_key = private_key) rescue raise ArgumentError, "Unsupported algorithm: #{ppk.algorithm}"
            end
          when 'ssh-rsa'
            ::OpenSSL::PKey::RSA.new.tap do |pkey|
              pkey.d, pkey.p, pkey.q, pkey.iqmp = Util.ssh_unpack(ppk.private_blob, :mpint, :mpint, :mpint, :mpint)
              pkey.dmp1 = pkey.d % (pkey.p - 1)
              pkey.dmq1 = pkey.d % (pkey.q - 1)

              # jruby-openssl requires e and n to be set last to obtain a valid private key (version 0.9.16)
              _, pkey.e, pkey.n = Util.ssh_unpack(ppk.public_blob, :string, :mpint, :mpint)
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

      module DSA
        def to_ppk
          PPK.new.tap do |ppk|
            ppk.algorithm = 'ssh-dss'
            ppk.public_blob = Util.ssh_pack('ssh-dss', p, q, g, pub_key)
            ppk.private_blob = Util.ssh_pack(priv_key)
          end
        end
      end

      module EC
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

      module RSA
        def to_ppk
          PPK.new.tap do |ppk|
            ppk.algorithm = 'ssh-rsa'
            ppk.public_blob = Util.ssh_pack('ssh-rsa', e, n)
            ppk.private_blob = Util.ssh_pack(d, p, q, iqmp)
          end
        end
      end

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

    OpenSSL::PKEY_CLASSES.each do |name, openssl_class|
      refine openssl_class do
        include OpenSSL.const_get(name)
      end if respond_to?(:refine, true)
    end

    refine ::OpenSSL::PKey.singleton_class do
      include OpenSSL::ClassMethods
    end if respond_to?(:refine, true)
  end
end
