# frozen_string_literal: true

module PuTTY
  module Key
    # Argon2 key derivation parameters for use with format 3.
    class Argon2Params
      # Returns the variant of Argon2 to use. `:d` for Argon2d, `:i` for Argon2i
      # or `:id` for Argon2id.
      #
      # @return [Symbol] The variant of Argon2 to use (`:d`, `:i` or `:id`).
      attr_reader :type

      # @return [Integer] The amount of memory to use (memory cost) in
      #   kibibytes.
      attr_reader :memory

      # @return [Integer] The number of parallel threads to use (parallelism
      #   degree / lanes).
      attr_reader :parallelism

      # @return [Integer] The number of passes or iterations to run (time cost),
      #   or `nil` to determine the time cost based on {#desired_time}.
      attr_reader :passes

      # @return [String] The salt to use, or `nil` if a random salt should be
      #   selected.
      attr_reader :salt

      # The minimum time that should be taken to derive keys in milliseconds.
      # Only used if {#passes} is `nil`.
      #
      # A number of passes will be chosen that take at least {#desired_time} to
      # compute a hash.
      #
      # @return [Numeric] The minimum time that should be taken to derive keys
      #   in milliseconds.
      attr_reader :desired_time

      # Initalizes a new {Argon2Params} instance with the specified parameters.
      #
      # @param type [Symbol] The variant of Argon2 to use (`:d`, `:i` or `:id`).
      # @param memory [Integer] The amount of memory to use (memory cost) in
      #   kibibytes.
      # @param parallelism [Integer] The number of parallel threads to use
      #   (parallelism degree / lanes).
      # @param passes [Integer] The number of passes or iterations to run (time
      #   cost), or `nil` to determine the time cost based on {#desired_time}.
      # @param salt [String] The salt to use, or `nil` if a random salt should
      #   be selected.
      # @param desired_time [Numeric] The minimum time that should be taken to
      #   derive keys in milliseconds.
      #
      # @raise [ArgumentError] If `type` is not either `:d`, `:i` or `:id`.
      # @raise [ArgumentError] If `memory` is not an `Integer`, is negative or
      #   greater than 2³².
      # @raise [ArgumentError] If `parallelism` is not an `Integer`, is negative
      #   or greater than 2³².
      # @raise [ArgumentError] If `passes` is specified, but is not an
      #   `Integer`, is negative or greater than 2³².
      # @raise [ArgumentError] If `salt` is specified, but is not a `String`.
      # @raise [ArgumentError] If `desired_time` is not `Numeric` or is
      #   negative.
      def initialize(type: :id, memory: 8192, parallelism: 1, passes: nil, salt: nil, desired_time: 100)
        raise ArgumentError, 'type must be :d, :i or :id' unless type == :id || type == :i || type == :d
        raise ArgumentError, 'memory must be a non-negative Integer' unless memory.kind_of?(Integer) && memory >= 0 && memory <= 2**32
        raise ArgumentError, 'parallelism must be a non-negative Integer' unless parallelism.kind_of?(Integer) && parallelism >= 0 && parallelism <= 2**32
        raise ArgumentError, 'passes must be nil or a non-negative Integer' if passes && !(passes.kind_of?(Integer) && passes >= 0 && passes <= 2**32)
        raise ArgumentError, 'salt must be nil or a String' if salt && !salt.kind_of?(String)
        raise ArgumentError, 'desired_time must be a non-negative Numeric' unless desired_time.kind_of?(Numeric) && desired_time >= 0 && desired_time <= 2**32

        @type = type
        @memory = memory
        @parallelism = parallelism
        @passes = passes
        @salt = salt
        @desired_time = desired_time
      end

      # Returns an instance of {Argon2Params} with the actual number of passes
      # and salt used.
      #
      # @param actual_passes [Integer] The number of passes or iterations used.
      # @param actual_salt [String] The actual salt used.
      #
      # @return [Argon2Params] An instance of {Argon2Params} with the given
      #   passes and salt.
      #
      # @raise [ArgumentError] If `actual_passes` is not a positive `Integer`.
      # @raise [ArgumentError] If `actual_salt` is not a `String`.
      def complete(passes, salt)
        raise ArgumentError, 'passes must not be nil' unless passes
        raise ArgumentError, 'salt must not be nil' unless salt
        if @passes == passes && @salt == salt
          self
        else
          Argon2Params.new(type: @type, memory: @memory, parallelism: @parallelism, passes: passes, salt: salt, desired_time: @desired_time)
        end
      end
    end
  end
end
