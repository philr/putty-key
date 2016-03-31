require 'openssl'
require 'stringio'

module PuTTY
  module Key
    # Utility methods used internally by PuTTY::Key.
    #
    # @private
    module Util
      # Encodes a list of values (String and OpenSSL::BN instances) according
      # to RFC 4251 section 5 (as strings and mpints).
      #
      # No encoding conversion is performed on Strings.
      #
      # @param [Array] values An Array of String and OpenSSL::BN instances to
      #   be encoded.
      #
      # @return [String] A binary String containing the encoded values.
      #
      # @raise NilValueError If a value is `nil`.
      def self.ssh_pack(*values)
        return ''.b if values.empty?

        values.map do |value|
          raise NilValueError, 'values must not contain nil elements' unless value

          if value.kind_of?(::OpenSSL::BN)
            value = value.to_i
            if value == 0
              value = ''
            else
              bytes = []

              if value > 0
                begin
                  bytes << (value & 0xff)
                  value = value >> 8
                end until value == 0

                # 0 pad if necessary to resolve ambiguity with negative numbers
                # in two's complement representation.
                bytes << 0 if bytes.last & 0x80 != 0
              else
                begin
                  bytes << (value & 0xff)
                  value = value >> 8
                end until value == -1 && bytes.last & 0x80 != 0
              end

              value = bytes.reverse!.pack('C*')
            end
          else
            value = value.to_s.b
          end

          [value.bytesize].pack('N') + value
        end.join
      end

      # Decodes a string containing RFC 4251 section 5 encoded string and
      # mpint values.
      #
      # @param [String] encoded A binary {String} containing the encoded values.
      # @param [Array<Symbol>] spec An array consisting of :string or :mpint
      #   elements describing the contents of encoded.
      #
      # @return [Array] An array of decoded (binary) {String} and {OpenSSL::BN}
      #   instances.
      #
      # @raise [ArgumentError] If `encoded` is `nil`.
      # @raise [ArgumentError] If `encoded` does not use the `ASCII_8BIT`
      #  (binary) encoding.
      # @raise [ArgumentError] If `spec` contains elements other than `:mpint`
      #   and `:string`.
      # @raise [FormatError] If the encoded structure is malformed.
      # @raise [FormatError] If `spec` contains more elements than are present
      #   within `encoded`.
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

          if length > 0
            encoded_value = io.read(length)
            raise FormatError, 'Missing value encountered' unless encoded_value
            raise FormatError, 'Truncated value encountered' unless encoded_value.bytesize == length
          else
            encoded_value = nil
          end

          case type
          when :string
            encoded_value || String.new
          when :mpint
            value = 0

            if encoded_value
              bytes = encoded_value.unpack('C*')
              bytes.each {|b| value = (value << 8) | b }

              if bytes.first & 0x80 != 0
                # A negative value. Reinterpret the bytes as the two's
                # complement representation of the negative integer.
                mask = 0xff
                (bytes.length - 1).times { mask = mask << 8 | 0xff }
                value = -(-value & mask)
              end
            end

            ::OpenSSL::BN.new(value)
          else
            raise ArgumentError, 'spec must contain only :string and :mpint elements'
          end
        end
      end
    end
    private_constant :Util
  end
end
