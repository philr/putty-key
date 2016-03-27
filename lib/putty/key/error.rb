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

    # Indicates that a nil value has been encountered.
    class NilValueError < Error
    end
    private_constant :NilValueError
  end
end
