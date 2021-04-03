module PuTTY
  module Key
    # Base class for all the error classes included in PuTTY::Key.
    class Error < StandardError
    end

    # Indicates that an error was encountered in a .ppk file that is being
    # read or converted to another format.
    class FormatError < Error
    end

    # Indicates that an operation cannot be performed with the current state
    # of the receiver.
    class InvalidStateError < Error
    end

    # Indicates that the specified elliptic curve is not supported.
    class UnsupportedCurveError < Error
    end

    # Indicates that libargon2 encountered an error hashing the passphrase to
    # derive the keys for a format 3 .ppk file.
    class Argon2Error < Error
      # The error code returned by the `argon2_hash` function.
      attr_reader :error_code

      # Initializes a new {Argon2Error}.
      #
      # @param error_code [Integer] The error code returned by the `argon2_hash`
      #   function.
      # @param message [String] A description of the error.
      def initialize(error_code, message)
        super(message)
        @error_code = error_code
      end
    end

    # Indicates that a nil value has been encountered.
    class NilValueError < Error
    end
    private_constant :NilValueError
  end
end
