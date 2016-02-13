require 'openssl'

module PuTTY
  module Key
    class PPK
      PRIVATE_MAC_KEY = 'putty-private-key-file-mac-key'.b.freeze
      DEFAULT_ENCRYPTION_TYPE = 'aes256-cbc'.freeze
      DEFAULT_FORMAT = 2

      attr_accessor :algorithm
      attr_accessor :comment
      attr_accessor :public_blob

      # The private blob from the PPK file. Note that when loading an encrypted
      # PPK file, this may include additional padding as a suffix.
      attr_accessor :private_blob

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

      def generate_encryption_key(passphrase, key_length)
        key = String.new.encode!(Encoding::ASCII_8BIT)
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

      def compute_private_mac(passphrase, encryption_type, padded_private_blob)
        key = ::OpenSSL::Digest::SHA1.new
        key.update(PRIVATE_MAC_KEY)
        key.update(passphrase) if passphrase
        data = Util.ssh_pack(@algorithm, encryption_type, @comment || '', @public_blob, padded_private_blob)
        ::OpenSSL::HMAC.hexdigest(::OpenSSL::Digest::SHA1.new, key.digest, data)
      end

      class Reader
        def self.open(path)
          File.open(path.to_s, 'rb') do |file|
            yield Reader.new(file)
          end
        end

        def initialize(file)
          @file = file
        end

        def field(name)
          line = read_line
          raise FormatError, "Expected field #{name}, but found #{line}" unless line.start_with?("#{name}: ")
          line.byteslice(name.bytesize + 2, line.bytesize - name.bytesize - 2)
        end

        def blob(name)
          lines = field("#{name}-Lines")
          raise FormatError, "Invalid value for #{name}-Lines" unless lines =~ /\A\d+\z/
          lines.to_i.times.map { read_line }.join("\n").unpack('m48').first
        end

        private

        def read_line
          @file.readline("\n").chomp("\n")
        rescue EOFError
          raise FormatError, 'Truncated ppk file detected'
        end
      end

      class Writer
        attr_reader :bytes_written

        def self.open(path)
          File.open(path.to_s, 'wb') do |file|
            yield Writer.new(file)
          end
        end

        def initialize(file)
          @file = file
          @bytes_written = 0
        end

        def field(name, value)
          write(name)
          write(': ')
          write(value.to_s)
          write_line
        end

        def blob(name, blob)
          lines = [blob].pack('m48').split("\n")
          field("#{name}-Lines", lines.length)
          lines.each do |line|
            write(line)
            write_line
          end
        end

        private

        def write_line
          write("\r\n")
        end

        def write(string)
          @bytes_written += @file.write(string)
        end
      end
    end
  end
end
