module PuTTY
  module Key
    class Error < StandardError
    end

    class FormatError < Error
    end

    class InvalidStateError < Error
    end
  end
end
