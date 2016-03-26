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
    # when loading or saving. As supported by PuTTY, files are always encrypted
    # using AES in CBC mode with a 256-bit key derived from the passphrase using
    # SHA-1.
    #
    # The {PPK} class supports files corresponding to PuTTY's format 2. Format 1
    # was only used briefly early on in the development of the .ppk format.
    class PPK
      # String used in the computation of the private MAC.
      MAC_KEY = 'putty-private-key-file-mac-key'#.b#.freeze
      private_constant :MAC_KEY

      # The default (and only supported) encryption algorithm.
      DEFAULT_ENCRYPTION_TYPE = 'aes256-cbc'.freeze

      # The default (and only supported) PuTTY private key file format.
      DEFAULT_FORMAT = 2

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
      # @raise [FormatError] If the .ppk file is malformed.
      def initialize(path = nil, passphrase = nil)
        passphrase = nil if passphrase && passphrase.to_s.empty?

        if path
          encryption_type, encrypted_private_blob, private_mac = Reader.open(path) do |reader|
            @algorithm = reader.field('PuTTY-User-Key-File-2')
            encryption_type = reader.field('Encryption')
            @comment = reader.field('Comment')
            @public_blob = reader.blob('Public')
            encrypted_private_blob = reader.blob('Private')
            private_mac = reader.field('Private-MAC')
            [encryption_type, encrypted_private_blob, private_mac]
          end

          if encryption_type == 'none'
            passphrase = nil
            @private_blob = encrypted_private_blob
          else
            raise FormatError, "The ppk file is encrypted with #{encryption_type}, which is not supported" unless encryption_type == DEFAULT_ENCRYPTION_TYPE
            raise ArgumentError, 'The ppk file is encrypted, a passphrase must be supplied' unless passphrase

            # PuTTY uses a zero IV.
            cipher = ::OpenSSL::Cipher::AES.new(256, :CBC)
            cipher.decrypt
            cipher.key = generate_encryption_key(passphrase, cipher.key_len)
            cipher.padding = 0
            @private_blob = cipher.update(encrypted_private_blob) + cipher.final
          end

          expected_private_mac = compute_private_mac(passphrase, encryption_type, @private_blob)

          unless private_mac == expected_private_mac
            raise ArgumentError, 'Incorrect passphrase supplied' if passphrase
            raise FormatError, "Invalid Private MAC (expected #{expected_private_mac}, but found #{private_mac})"
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
      #   and currently only supports `2`.
      #
      # @return [Integer] The number of bytes written to the file.
      #
      # @raise [InvalidStateError] If either of the {#algorithm},
      #   {#private_blob} or {#public_blob} attributes have not been set.
      # @raise [ArgumentError] If `path` is nil.
      # @raise [ArgumentError] If a passphrase has been specified and
      #   `encryption_type` is not `'aes256-cbc'`.
      # @raise [ArgumentError] If `format` is not `2`.
      # @raise [Errno::ENOENT] If a directory specified by `path` does not
      #   exist.
      def save(path, passphrase = nil, encryption_type: DEFAULT_ENCRYPTION_TYPE, format: DEFAULT_FORMAT)
        raise InvalidStateError, 'algorithm must be set before calling save' unless @algorithm
        raise InvalidStateError, 'public_blob must be set before calling save' unless @public_blob
        raise InvalidStateError, 'private_blob must be set before calling save' unless @private_blob

        passphrase = nil if passphrase && passphrase.to_s.empty?
        encryption_type = 'none' unless passphrase

        raise ArgumentError, 'An output path must be specified' unless path

        if passphrase
          raise ArgumentError, 'An encryption_type must be specified if a passphrase is specified' unless encryption_type
          raise ArgumentError, "Unsupported encryption_type: #{encryption_type}" unless encryption_type == DEFAULT_ENCRYPTION_TYPE
        end

        raise ArgumentError, 'A format must be specified' unless format
        raise ArgumentError, "Unsupported format: #{format}" unless format == DEFAULT_FORMAT

        padded_private_blob = @private_blob

        if passphrase
          # Pad using an SHA-1 hash of the unpadded private blob in order to
          # prevent an easily known plaintext attack on the last block.
          cipher = ::OpenSSL::Cipher::AES.new(256, :CBC)
          cipher.encrypt
          padding_length = cipher.block_size - (padded_private_blob.bytesize % cipher.block_size)
          padded_private_blob += ::OpenSSL::Digest::SHA1.new(padded_private_blob).digest[0, padding_length]

          # PuTTY uses a zero IV.
          cipher.key = generate_encryption_key(passphrase, cipher.key_len)
          cipher.padding = 0
          encrypted_private_blob = cipher.update(padded_private_blob) + cipher.final
        else
          encrypted_private_blob = private_blob
        end

        private_mac = compute_private_mac(passphrase, encryption_type, padded_private_blob)

        Writer.open(path) do |writer|
          writer.field('PuTTY-User-Key-File-2', @algorithm)
          writer.field('Encryption', encryption_type)
          writer.field('Comment', @comment)
          writer.blob('Public', @public_blob)
          writer.blob('Private', encrypted_private_blob)
          writer.field('Private-MAC', private_mac)
        end
      end

      private

      # Generates an encryption key of the specified length from a passphrase.
      #
      # @param passphrase [String] The passphrase to use.
      # @param key_length [Integer] The length of the desired key in bytes.
      #
      # @return [String] The generated key.
      def generate_encryption_key(passphrase, key_length)
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

      # Computes the value of the Private-MAC field given the passphrase,
      # encryption type and padded private blob (the value of the private blob
      # after padding bytes have been appended prior to encryption).
      #
      # @param passphrase [String] The encryption passphrase.
      # @param encryption_type [String] The value of the Encryption field.
      # @param padded_private_blob [String] The private blob after padding bytes
      #   have been appended prior to encryption.
      #
      # @return [String] The computed private MAC.
      def compute_private_mac(passphrase, encryption_type, padded_private_blob)
        key = ::OpenSSL::Digest::SHA1.new
        key.update(MAC_KEY)
        key.update(passphrase) if passphrase
        data = Util.ssh_pack(@algorithm, encryption_type, @comment || '', @public_blob, padded_private_blob)
        ::OpenSSL::HMAC.hexdigest(::OpenSSL::Digest::SHA1.new, key.digest, data)
      end

      # Handles reading .ppk files.
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
          lines = field("#{name}-Lines")
          raise FormatError, "Invalid value for #{name}-Lines" unless lines =~ /\A\d+\z/
          lines.to_i.times.map { read_line }.join("\n").unpack('m48').first
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
        # @param value [String] The field value.
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
