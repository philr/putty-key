require 'openssl'
require 'stringio'

module PuTTY
  module Key
    module Util
      # Encodes a list of values (String and OpenSSL::BN instances) according
      # to RFC 4251 section 5.
      #
      # No encoding conversion is performed on Strings.
      #
      # @param [Array] *values An Array of String and OpenSSL::BN instances to be
      #   encoded.
      # @return [String] A binary String containing the encoded values.
      def self.ssh_pack(*values)
        return ''.b if values.empty?

        values.map do |value|
          raise ArgumentError, 'values elements must not be nil' unless value

          if value.kind_of?(::OpenSSL::BN)
            value.to_s(0)
          else
            value = value.to_s.b
            [value.bytesize].pack('N') + value
          end
        end.join
      end

      # Decodes a string containing RFC 4251 section 5 encoded string and
      # mpint values.
      #
      # @param [String] encoded A binary String containing the encoded values.
      # @param [Array<Symbol>] *spec An array consisting of :string or :mpint
      #   elements describing the contents of encoded.
      # @return [Array] An array of decoded (binary) String and OpenSSL::BN
      #   instances.
      def self.ssh_unpack(encoded, *spec)
        raise ArgumentError, 'encoded must not be nil' unless encoded
        encoded = encoded.to_s
        raise ArgumentError, 'encoded must be a binary String' unless encoded.encoding == Encoding::ASCII_8BIT

        io = StringIO.new(encoded)

        spec.map do |type|
          length_bytes = io.read(4)
          raise FormatError, 'spec contains more elements than are contained within the encoded String' unless length_bytes
          raise FormatError, 'Truncated length encountered' unless length_bytes.bytesize == 4

          length = length_bytes.unpack('N').first

          encoded_value = io.read(length)
          raise FormatError, 'Missing value encountered' unless encoded_value
          raise FormatError, 'Truncated value encountered' unless encoded_value.bytesize == length

          case type
          when :string
            encoded_value
          when :mpint
            ::OpenSSL::BN.new(length_bytes + encoded_value, 0)
          else
            raise ArgumentError, 'spec must contain only :string and :mpint elements'
          end
        end
      end
    end
  end
end
