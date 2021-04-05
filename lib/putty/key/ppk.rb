# frozen_string_literal: true

require 'openssl'

module PuTTY
  module Key
    # Represents a PuTTY private key (.ppk) file.
    #
    # The {PPK} {#initialize constructor} can be used to either create an
    # uninitialized key or to load a .ppk file.
    #
    # The {#save} method can be used to save a {PPK} instance to a .ppk file.
    #
    # The {#algorithm}, {#comment}, {#public_blob} and {#private_blob}
    # attributes provide access to the high level fields of the PuTTY private
    # key as binary `String` instances. The structure of the two blobs will vary
    # based on the algorithm.
    #
    # Encrypted .ppk files can be read and written by specifying a passphrase
    # when loading or saving. Files are encrypted using AES in CBC mode with a
    # 256-bit key derived from the passphrase.
    #
    # The {PPK} class supports files corresponding to PuTTY's formats 2 and 3.
    # Format 1 (not supported) was only used briefly early on in the development
    # of the .ppk format and was never released. Format 2 is supported by PuTTY
    # version 0.52 onwards. Format 3 is supported by PuTTY version 0.75 onwards.
    # {PPK#save} defaults to format 2. Use the `format` parameter to select
    # format 3.
    #
    # libargon2 (https://github.com/P-H-C/phc-winner-argon2) is required to load
    # and save encrypted format 3 files. Binaries are typically available with
    # your OS distribution. For Windows, binaries are available at
    # https://github.com/philr/argon2-windows/releases - use either
    # Argon2OptDll.dll for CPUs supporting AVX or Argon2RefDll.dll otherwise.
    class PPK
      # String used in the computation of the format 3 MAC.
      FORMAT_2_MAC_KEY = 'putty-private-key-file-mac-key'
      private_constant :FORMAT_2_MAC_KEY

      # Length of the key used for the format 3 MAC.
      FORMAT_3_MAC_KEY_LENGTH = 32
      private_constant :FORMAT_3_MAC_KEY_LENGTH

      # The default (and only supported) encryption algorithm.
      DEFAULT_ENCRYPTION_TYPE = 'aes256-cbc'.freeze

      # The default PuTTY private key file format.
      DEFAULT_FORMAT = 2

      # The mimimum supported PuTTY private key file format.
      MINIMUM_FORMAT = 2

      # The maximum supported PuTTY private key file format.
      MAXIMUM_FORMAT = 3

      # Default Argon2 key derivation parameters for use with format 3.
      DEFAULT_ARGON2_PARAMS = Argon2Params.new.freeze

      # The key's algorithm, for example, 'ssh-rsa' or 'ssh-dss'.
      #
      # @return [String] The key's algorithm, for example, 'ssh-rsa' or
      #   'ssh-dss'.
      attr_accessor :algorithm

      # A comment to describe the PuTTY private key.
      #
      # @return [String] A comment to describe the PuTTY private key.
      attr_accessor :comment

      # Get or set the public component of the key.
      #
      # @return [String] The public component of the key.
      attr_accessor :public_blob

      # The private component of the key (after decryption when loading and
      # before encryption when saving).
      #
      # Note that when loading an encrypted .ppk file, this may include
      # additional 'random' suffix used as padding.
      #
      # @return [String] The private component of the key
      attr_accessor :private_blob

      # Constructs a new {PPK} instance either uninitialized, or by loading a
      # .ppk file.
      #
      # @param path [Object] Set to the path of a .ppk file to load the file.
      #   Leave as `nil` to leave the new {PPK} instance uninitialized.
      # @param passphrase [String] The passphrase to use when loading an
      #   encrypted .ppk file.
      #
      # @raise [Errno::ENOENT] If the file specified by `path` does not exist.
      # @raise [ArgumentError] If the .ppk file was encrypted, but either no
      #   passphrase or an incorrect passphrase was supplied.
      # @raise [FormatError] If the .ppk file is malformed or not supported.
      # @raise [LoadError] If opening an encrypted format 3 .ppk file and
      #   libargon2 could not be loaded.
      # @raise [Argon2Error] If opening an encrypted format 3 .ppk file and
      #   libargon2 reported an error hashing the passphrase.
      def initialize(path = nil, passphrase = nil)
        passphrase = nil if passphrase && passphrase.to_s.empty?

        if path
          Reader.open(path) do |reader|
            format, @algorithm = reader.field_matching(/PuTTY-User-Key-File-(\d+)/)
            format = format.to_i
            raise FormatError, "The ppk file is using a format that is too new (#{format})" if format > MAXIMUM_FORMAT
            raise FormatError, "The ppk file is using an old unsupported format (#{format})" if format < MINIMUM_FORMAT

            encryption_type = reader.field('Encryption')
            @comment = reader.field('Comment')
            @public_blob = reader.blob('Public')


            if encryption_type == 'none'
              passphrase = nil
              mac_key = derive_keys(format).first
              @private_blob = reader.blob('Private')
            else
              raise FormatError, "The ppk file is encrypted with #{encryption_type}, which is not supported" unless encryption_type == DEFAULT_ENCRYPTION_TYPE
              raise ArgumentError, 'The ppk file is encrypted, a passphrase must be supplied' unless passphrase

              argon2_params = if format >= 3
                type = get_argon2_type(reader.field('Key-Derivation'))
                memory = reader.unsigned_integer('Argon2-Memory', maximum: 2**32)
                passes = reader.unsigned_integer('Argon2-Passes', maximum: 2**32)
                parallelism = reader.unsigned_integer('Argon2-Parallelism', maximum: 2**32)
                salt = reader.field('Argon2-Salt')
                unless salt =~ /\A(?:[0-9a-fA-F]{2})+\z/
                  raise FormatError, "Expected the Argon2-Salt field to be a hex string, but found #{salt}"
                end

                Argon2Params.new(type: type, memory: memory, passes: passes, parallelism: parallelism, salt: [salt].pack('H*'))
              end

              cipher = ::OpenSSL::Cipher::AES.new(256, :CBC)
              cipher.decrypt
              mac_key, cipher.key, cipher.iv = derive_keys(format, cipher, passphrase, argon2_params)
              cipher.padding = 0
              encrypted_private_blob = reader.blob('Private')

              @private_blob = if encrypted_private_blob.bytesize > 0
                partial = cipher.update(encrypted_private_blob)
                final = cipher.final
                partial + final
              else
                encrypted_private_blob
              end
            end

            private_mac = reader.field('Private-MAC')
            expected_private_mac = compute_private_mac(format, mac_key, encryption_type, @private_blob)

            unless private_mac == expected_private_mac
              raise ArgumentError, 'Incorrect passphrase supplied' if passphrase
              raise FormatError, "Invalid Private MAC (expected #{expected_private_mac}, but found #{private_mac})"
            end
          end
        end
      end

      # Saves this PuTTY private key instance to a .ppk file.
      #
      # The {#algorithm}, {#private_blob} and {#public_blob} attributes must
      # have been set before calling {#save}.
      #
      # @param path [Object] The path to write to. If a file already exists, it
      #   will be overwritten.
      # @param passphrase [String] Set `passphrase` to encrypt the .ppk file
      #   using the specified passphrase. Leave as `nil` to create an
      #   unencrypted .ppk file.
      # @param encryption_type [String] The encryption algorithm to use.
      #   Defaults to and currently only supports `'aes256-cbc'`.
      # @param format [Integer] The format of .ppk file to create. Defaults to
      #   `2`. Supports `2` and `3`.
      # @param argon2_params [Argon2Params] The parameters to use with Argon2
      #   to derive the encryption key, initialization vector and MAC key when
      #   saving an encrypted format 3 .ppk file.
      #
      # @return [Integer] The number of bytes written to the file.
      #
      # @raise [InvalidStateError] If either of the {#algorithm},
      #   {#private_blob} or {#public_blob} attributes have not been set.
      # @raise [ArgumentError] If `path` is nil.
      # @raise [ArgumentError] If a passphrase has been specified and
      #   `encryption_type` is not `'aes256-cbc'`.
      # @raise [ArgumentError] If `format` is not `2` or `3`.
      # @raise [ArgumentError] If `argon2_params` is `nil`, a passphrase has
      #   been specified and `format` is `3`.
      # @raise [Errno::ENOENT] If a directory specified by `path` does not
      #   exist.
      # @raise [LoadError] If saving an encrypted format 3 .ppk file and
      #   libargon2 could not be loaded.
      # @raise [Argon2Error] If saving an encrypted format 3 .ppk file and
      #   libargon2 reported an error hashing the passphrase.
      def save(path, passphrase = nil, encryption_type: DEFAULT_ENCRYPTION_TYPE, format: DEFAULT_FORMAT, argon2_params: DEFAULT_ARGON2_PARAMS)
        raise InvalidStateError, 'algorithm must be set before calling save' unless @algorithm
        raise InvalidStateError, 'public_blob must be set before calling save' unless @public_blob
        raise InvalidStateError, 'private_blob must be set before calling save' unless @private_blob

        raise ArgumentError, 'An output path must be specified' unless path

        passphrase = nil if passphrase && passphrase.to_s.empty?

        raise ArgumentError, 'A format must be specified' unless format
        raise ArgumentError, "Unsupported format: #{format}" unless format >= MINIMUM_FORMAT && format <= MAXIMUM_FORMAT

        if passphrase
          raise ArgumentError, 'An encryption_type must be specified if a passphrase is specified' unless encryption_type
          raise ArgumentError, "Unsupported encryption_type: #{encryption_type}" unless encryption_type == DEFAULT_ENCRYPTION_TYPE
          raise ArgumentError, 'argon2_params must be specified if a passphrase is specified with format 3' unless format < 3 || argon2_params

          cipher = ::OpenSSL::Cipher::AES.new(256, :CBC)
          cipher.encrypt
          mac_key, cipher.key, cipher.iv, kdf_params = derive_keys(format, cipher, passphrase, argon2_params)
          cipher.padding = 0

          # Pad using an SHA-1 hash of the unpadded private blob in order to
          # prevent an easily known plaintext attack on the last block.
          padding_length = cipher.block_size - ((@private_blob.bytesize - 1) % cipher.block_size) - 1
          padded_private_blob = @private_blob
          padded_private_blob += ::OpenSSL::Digest::SHA1.new(@private_blob).digest.byteslice(0, padding_length) if padding_length > 0

          encrypted_private_blob = if padded_private_blob.bytesize > 0
            partial = cipher.update(padded_private_blob)
            final = cipher.final
            partial + final
          else
            padded_private_blob
          end
        else
          encryption_type = 'none'
          mac_key = derive_keys(format).first
          kdf_params = nil
          padded_private_blob = @private_blob
          encrypted_private_blob = padded_private_blob
        end

        private_mac = compute_private_mac(format, mac_key, encryption_type, padded_private_blob)

        Writer.open(path) do |writer|
          writer.field("PuTTY-User-Key-File-#{format}", @algorithm)
          writer.field('Encryption', encryption_type)
          writer.field('Comment', @comment)
          writer.blob('Public', @public_blob)
          if kdf_params
            # Only Argon2 is currently supported.
            writer.field('Key-Derivation', "Argon2#{kdf_params.type}")
            writer.field('Argon2-Memory', kdf_params.memory)
            writer.field('Argon2-Passes', kdf_params.passes)
            writer.field('Argon2-Parallelism', kdf_params.parallelism)
            writer.field('Argon2-Salt', kdf_params.salt.unpack('H*').first)
          end
          writer.blob('Private', encrypted_private_blob)
          writer.field('Private-MAC', private_mac)
        end
      end

      private

      # Returns the Argon2 type (`:d`, `:i` or `:id`) corresponding to the value
      # of the Key-Derivation field in the .ppk file.
      #
      # @param key_derivation [String] The value of the Key-Derivation field.
      #
      # @return [Symbol] The Argon2 type.
      #
      # @raise [FormatError] If `key_derivation` is unrecognized.
      def get_argon2_type(key_derivation)
        unless key_derivation =~ /\AArgon2(d|id?)\z/
          raise FormatError, "Unrecognized key derivation type: #{key_derivation}"
        end

        $1.to_sym
      end

      # Derives the MAC key, encryption key and initialization vector from the
      # passphrase (if the file is encrypted).
      #
      # @param format [Integer] The format of the .ppk file.
      # @param cipher [OpenSSL::Cipher] The cipher being used to encrypt or
      #   decrypt the .ppk file or `nil` if not encrypted.
      # @param passphrase [String] The passphrase used in the derivation or
      #   `nil` if the .ppk file is not encrypted. The raw bytes of the
      #   passphrase are used in the derivation.
      # @param argon2_params [Argon2Params] Parameters used with the Argon2 hash
      #   function. May be `nil` if the .ppk file is not encrypted or `format`
      #   is less than 3.
      #
      # @return [Array<String, String, String, Argon2Params>] The MAC key,
      #   encryption key, initialization vector and final Argon2 parameters.
      #   The encryption key and initialization vector will be `nil` if `cipher`
      #   is `nil`. The final Argon2 parameters will only be set if `format` is
      #   greater than or equal to 3 and `cipher` is not nil. The final Argon2
      #   parameters will differ from `argon2_params` if the salt and passes
      #   options were left unspecified.
      #
      # @raise [LoadError] If `format` is at least 3, `cipher` is specified and
      #   libargon2 could not be loaded.
      # @raise [Argon2Error] If `format` is at least 3, `cipher` is specified
      #   and libargon2 reported an error hashing the passphrase.
      def derive_keys(format, cipher = nil, passphrase = nil, argon2_params = nil)
        if format >= 3
          return derive_format_3_keys(cipher, passphrase, argon2_params) if cipher
          return [''.b, nil, nil, nil]
        end

        mac_key = derive_format_2_mac_key(passphrase)

        if cipher
          key = derive_format_2_encryption_key(passphrase, cipher.key_len)
          iv = "\0".b * cipher.iv_len
        else
          key = nil
          iv = nil
        end

        [mac_key, key, iv, nil]
      end

      # Initializes the Argon2 salt if required, determines the number of passes
      # to use to meet the time requirement unless preset and then derives the
      # MAC key, encryption key and initalization vector.
      #
      # @param cipher [OpenSSL::Cipher] The cipher being used to encrypt or
      #   decrypt the .ppk file.
      # @param passphrase [String] The passphrase used in the derivation. The
      #   raw bytes of the passphrase are used in the derivation.
      # @param argon2_params [Argon2Params] Parameters used with the Argon2 hash
      #   function.
      #
      # @return [Array<String, String, String, Argon2Params>] The MAC key,
      #   encryption key, initialization vector and final Argon2 parameters.
      #   The encryption key and initialization vector will be `nil` if `cipher`
      #   is `nil`. The final Argon2 parameters will differ from `argon2_params`
      #   if the salt and passes options were left unspecified.
      #
      # @raise [LoadError] If libargon2 could not be loaded.
      # @raise [Argon2Error] If libargon2 reported an error hashing the
      #   passphrase.
      def derive_format_3_keys(cipher, passphrase, argon2_params)
        # Defer loading of libargon2 to avoid a mandatory dependency.
        require_relative 'libargon2'

        salt = argon2_params.salt || ::OpenSSL::Random.random_bytes(16)
        passphrase_ptr = pointer_for_bytes(passphrase)
        salt_ptr = pointer_for_bytes(salt)
        hash_ptr = FFI::MemoryPointer.new(:char, cipher.key_len + cipher.iv_len + FORMAT_3_MAC_KEY_LENGTH)
        begin
          passes = argon2_params.passes
          if passes
            argon2_hash(argon2_params.type, argon2_params.passes, argon2_params.memory, argon2_params.parallelism, passphrase_ptr, salt_ptr, hash_ptr)
          else
            # Only require the time taken to be approximately correct. Scale up
            # geometrically using Fibonacci numbers (as per PuTTY's
            # implementation).
            prev_passes = 1
            passes = 1

            loop do
              start_time = Process.clock_gettime(Process::CLOCK_MONOTONIC)
              argon2_hash(argon2_params.type, passes, argon2_params.memory, argon2_params.parallelism, passphrase_ptr, salt_ptr, hash_ptr)
              elapsed = (Process.clock_gettime(Process::CLOCK_MONOTONIC) - start_time) * 1000
              break if (elapsed >= argon2_params.desired_time)
              hash_ptr.clear
              new_passes = passes + prev_passes
              break if new_passes > 2**32 # maximum allowed by argon2_hash parameter data type
              prev_passes, passes = passes, new_passes
            end
          end

          passphrase_ptr.clear
          key = hash_ptr.get_bytes(0, cipher.key_len)
          iv = hash_ptr.get_bytes(cipher.key_len, cipher.iv_len)
          mac_key = hash_ptr.get_bytes(cipher.key_len + cipher.iv_len, FORMAT_3_MAC_KEY_LENGTH)
          argon2_params = argon2_params.complete(passes, salt)
          hash_ptr.clear
          [mac_key, key, iv, argon2_params]
        ensure
          # Calling free isn't actually required, but this releases the memory
          # sooner.
          hash_ptr.free
          salt_ptr.free
          passphrase_ptr.free
        end
      end

      # Creates an `FFI::MemoryPointer` containing the raw bytes from `string`
      # without a null terminator.
      #
      # @param string [String] The bytes to use for the `FFI::MemoryPointer`.
      #
      # @return [FFI::MemoryPointer] A new `FFI::MemoryPointer` containing the
      #   raw bytes from `string`.
      def pointer_for_bytes(string)
        FFI::MemoryPointer.new(:char, string.bytesize).tap do |ptr|
          ptr.put_bytes(0, string)
        end
      end

      # Calls the libargon2 `argon2_hash` function to obtain a raw hash using
      # version 13 of the algorithm.
      #
      # @param type [Symbol] The variant of Argon2 to use. (`:d`, `:i` or
      #   `:id`).
      # @param iterations [Integer] The number of iterations to use.
      # @param memory [Integer] Memory usage in kibibytes.
      # @param passhrase [FFI::MemoryPointer] The passphrase.
      # @param salt [FFI::MemoryPointer] The salt.
      # @param hash [FFI::MemoryPointer] A buffer to write the raw hash to.
      #
      # @raise [Argon2Error] If `argon2_hash` returns an error.
      def argon2_hash(type, iterations, memory, parallelism, passphrase, salt, hash)
        res = Libargon2.argon2_hash(iterations, memory, parallelism,
          passphrase, passphrase.size, salt, salt.size,
          hash, hash.size, FFI::Pointer::NULL, 0, type, :version_13)

        unless res == Libargon2::ARGON2_OK
          raise Argon2Error.new(res, Libargon2.argon2_error_message(res))
        end
      end

      # Derives an encryption key of the specified length from a passphrase for
      # use in format 2 files.
      #
      # @param passphrase [String] The passphrase to use.
      # @param key_length [Integer] The length of the desired key in bytes.
      #
      # @return [String] The derived encryption key.
      def derive_format_2_encryption_key(passphrase, key_length)
        key = String.new
        key_digest = ::OpenSSL::Digest::SHA1.new
        iteration = 0

        while true
          key_digest.update([iteration].pack('N'))
          key_digest.update(passphrase.bytes.pack('c*'))
          key += key_digest.digest

          break if key.bytesize > key_length

          key_digest.reset
          iteration += 1
        end

        key[0, key_length]
      end

      # Derives a MAC key from a passphrase for use in format 2 files.
      #
      # @param passphrase [String] The passphrase to use or `nil` if not
      #   encrypted.
      #
      # @return [String] The derived MAC key.
      def derive_format_2_mac_key(passphrase)
        key = ::OpenSSL::Digest::SHA1.new
        key.update(FORMAT_2_MAC_KEY)
        key.update(passphrase) if passphrase
        key.digest
      end

      # Computes the value of the Private-MAC field given the passphrase,
      # encryption type and padded private blob (the value of the private blob
      # after padding bytes have been appended prior to encryption).
      #
      # @param format [Integer] The format of the .ppk file.
      # @param passphrase [String] The encryption passphrase.
      # @param encryption_type [String] The value of the Encryption field.
      # @param padded_private_blob [String] The private blob after padding bytes
      #   have been appended prior to encryption.
      #
      # @return [String] The computed private MAC.
      def compute_private_mac(format, mac_key, encryption_type, padded_private_blob)
        digest = format <= 2 ? ::OpenSSL::Digest::SHA1 : ::OpenSSL::Digest::SHA256
        data = Util.ssh_pack(@algorithm, encryption_type, @comment || '', @public_blob, padded_private_blob)
        ::OpenSSL::HMAC.hexdigest(digest.new, mac_key, data)
      end

      # Handles reading .ppk files.
      #
      # @private
      class Reader
        # Opens a .ppk file for reading, creates a new instance of `Reader` and
        # yields it to the caller.
        #
        # @param path [Object] The path of the .ppk file to be read.
        #
        # @return [Object] The result of yielding to the caller.
        #
        # raise [Errno::ENOENT] If the file specified by `path` does not exist.
        def self.open(path)
          File.open(path.to_s, 'rb') do |file|
            yield Reader.new(file)
          end
        end

        # Initializes a new {Reader} with an {IO} to read from.
        #
        # @param file [IO] The file to read from.
        def initialize(file)
          @file = file
        end

        # Reads the next field from the file.
        #
        # @param name [String] The expected field name.
        #
        # @return [String] The value of the field.
        #
        # @raise [FormatError] If the current position in the file was not the
        #   start of a field with the expected name.
        def field(name)
          line = read_line
          raise FormatError, "Expected field #{name}, but found #{line}" unless line.start_with?("#{name}: ")
          line.byteslice(name.bytesize + 2, line.bytesize - name.bytesize - 2)
        end

        # Reads the next field from the file.
        #
        # @param name_regexp [Regexp] A `Regexp` that matches the expected field
        #   name.
        #
        # @return [String] The value of the field if the regular expression has
        #   no captures.
        # @return [Array] An array containing the regular expression captures as
        #   the first elements and the value of the field as the last element.
        #
        # @raise [FormatError] If the current position in the file was not the
        #   start of a field with the expected name.
        def field_matching(name_regexp)
          line = read_line
          line_regexp = Regexp.new("\\A#{name_regexp.source}: ", name_regexp.options)
          match = line_regexp.match(line)
          raise FormatError, "Expected field matching #{name_regexp}, but found #{line}" unless match
          prefix = match[0]
          value = line.byteslice(prefix.bytesize, line.bytesize - prefix.bytesize)
          captures = match.captures
          captures.empty? ? value : captures + [value]
        end

        # Reads the next field from the file as an unsigned integer.
        #
        # @param name [String] The expected field name.
        #
        # @return [Integer] The value of the field.
        #
        # @raise [FormatError] If the current position in the file was not the
        #   start of a field with the expected name.
        # @raise [FormatError] If the field did not contain a positive integer.
        def unsigned_integer(name, maximum: nil)
          value = field(name)
          value = value =~ /\A[0-9]+\z/ && value.to_i
          raise FormatError, "Expected field #{name} to contain an unsigned integer value, but found #{value}" unless value
          raise FormatError, "Expected field #{name} to have a maximum of #{maximum}, but found #{value}" if maximum && value > maximum
          value
        end

        # Reads a blob from the file consisting of a Lines field whose value
        # gives the number of Base64 encoded lines in the blob.
        #
        # @return [String] The Base64-decoded value of the blob.
        #
        # @raise [FormatError] If there is not a blob starting at the current
        #   file position.
        # @raise [FormatError] If the value of the Lines field is not a
        #   positive integer.
        def blob(name)
          lines = unsigned_integer("#{name}-Lines")
          lines.times.map { read_line }.join("\n").unpack('m48').first
        end

        private

        # Reads a single new-line (\n or \r\n) terminated line from the file,
        # removing the new-line character.
        #
        # @return [String] The line.
        #
        # @raise [FormatError] If the end of file was detected before reading a
        #   line.
        def read_line
          @file.readline("\n").chomp("\n")
        rescue EOFError
          raise FormatError, 'Truncated ppk file detected'
        end
      end
      private_constant :Reader

      # Handles writing .ppk files.
      #
      # @private
      class Writer
        # The number of bytes that have been written.
        #
        # @return [Integer] The number of bytes that have been written.
        attr_reader :bytes_written

        # Opens a .ppk file for writing, creates a new instance of `Writer` and
        # yields it to the caller.
        #
        # @param path [Object] The path of the .ppk file to be written.
        #
        # @return [Object] The result of yielding to the caller.
        #
        # @raise [Errno::ENOENT] If a directory specified by `path` does not
        #   exist.
        def self.open(path)
          File.open(path.to_s, 'wb') do |file|
            yield Writer.new(file)
          end
        end

        # Initializes a new {Writer} with an {IO} to write to.
        #
        # @param file [IO] The file to write to.
        def initialize(file)
          @file = file
          @bytes_written = 0
        end

        # Writes a field to the file.
        #
        # @param name [String] The field name.
        # @param value [Object] The field value.
        def field(name, value)
          write(name)
          write(': ')
          write(value.to_s)
          write_line
        end

        # Writes a blob to the file (Lines field and Base64 encoded value).
        #
        # @param name [String] The name of the blob (used as a prefix for the
        #   lines field).
        # @param blob [String] The value of the blob. This is Base64 encoded
        #   before being written to the file.
        def blob(name, blob)
          lines = [blob].pack('m48').split("\n")
          field("#{name}-Lines", lines.length)
          lines.each do |line|
            write(line)
            write_line
          end
        end

        private

        # Writes a line separator to the file (\r\n on all platforms).
        def write_line
          write("\r\n")
        end

        # Writes a string to the file.
        #
        # @param string [String] The string to be written.
        def write(string)
          @bytes_written += @file.write(string)
        end
      end
      private_constant :Writer
    end
  end
end
