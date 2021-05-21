# frozen_string_literal: true

require_relative 'test_helper'
require 'pathname'

class PPKTest < Minitest::Test
  TEST_COMMENT = 'This is a test ppk file'.b
  TEST_PUBLIC_BLOB = "\x00\x00\x00\x04test\x00\x00\x00\x4AThis is the public blob from a ppk file created for testing purposes only.".b
  TEST_PRIVATE_BLOB = "\x00\x00\x00\x77This is the private blob from a ppk file created for testing purposes only. It is slightly longer than the public blob.".b

  def test_initialize
    ppk = PuTTY::Key::PPK.new
    assert_nil(ppk.algorithm)
    assert_nil(ppk.comment)
    assert_nil(ppk.public_blob)
    assert_nil(ppk.private_blob)
  end

  def test_initialize_invalid_format_too_old
    format = PuTTY::Key::PPK::MINIMUM_FORMAT - 1
    error = assert_raises(PuTTY::Key::FormatError) { PuTTY::Key::PPK.new(fixture_path("test-invalid-format-#{format}.ppk")) }
    assert_equal("The ppk file is using an old unsupported format (#{format})", error.message)
  end

  def test_initialize_invalid_format_too_new
    format = PuTTY::Key::PPK::MAXIMUM_FORMAT + 1
    error = assert_raises(PuTTY::Key::FormatError) { PuTTY::Key::PPK.new(fixture_path("test-invalid-format-#{format}.ppk")) }
    assert_equal("The ppk file is using a format that is too new (#{format})", error.message)
  end

  [:encryption_type, :key_derivation, :argon2_memory, :argon2_memory_maximum,
    :argon2_passes, :argon2_passes_maximum, :argon2_parallelism,
    :argon2_parallelism_maximum, :argon2_salt
  ].each do |feature|
    define_method("test_initialize_invalid_#{feature}") do
      path = fixture_path("test-invalid-#{feature.to_s.gsub('_', '-')}.ppk")
      assert_raises(PuTTY::Key::FormatError) { PuTTY::Key::PPK.new(path, 'Test Passphrase') }
    end
  end

  [:private_mac, :blob_lines].each do |feature|
    define_method("test_initialize_invalid_#{feature}") do
      path = fixture_path("test-invalid-#{feature.to_s.gsub('_', '-')}.ppk")
      assert_raises(PuTTY::Key::FormatError) { PuTTY::Key::PPK.new(path) }
    end
  end

  def test_initialize_invalid_argon2_memory_for_libargon2
    # Allowed by Argon2Params, but not by libargon2.
    path = fixture_path("test-invalid-argon2-memory-for-libargon2.ppk")
    assert_raises(PuTTY::Key::Argon2Error) { PuTTY::Key::PPK.new(path, 'Test Passphrase') }
  end

  def test_initialize_file_not_exists
    temp_dir do |dir|
      assert_raises(Errno::ENOENT) { PuTTY::Key::PPK.new(File.join(dir, 'missing')) }
    end
  end

  def test_initialize_non_ppk
    assert_raises(PuTTY::Key::FormatError) { PuTTY::Key::PPK.new(fixture_path('rsa-2048.pem')) }
  end

  def test_initialize_truncated
    assert_raises(PuTTY::Key::FormatError) { PuTTY::Key::PPK.new(fixture_path('test-truncated.ppk')) }
  end

  def assert_test_ppk_properties(ppk, comment: TEST_COMMENT, public_blob: TEST_PUBLIC_BLOB, private_blob: TEST_PRIVATE_BLOB, encrypted: false)
    assert_equal(Encoding::ASCII_8BIT, ppk.algorithm.encoding)
    assert_equal(Encoding::ASCII_8BIT, ppk.comment.encoding)
    assert_equal(Encoding::ASCII_8BIT, ppk.public_blob.encoding)
    assert_equal(Encoding::ASCII_8BIT, ppk.private_blob.encoding)
    assert_equal('test'.b, ppk.algorithm)
    assert_equal(comment, ppk.comment)
    assert_equal(public_blob, ppk.public_blob)

    if encrypted
      # When loading an encrypted ppk file, the padding added to the private blob cannot be removed.
      assert(ppk.private_blob.start_with?(private_blob), "Private blob does not start with #{TEST_PRIVATE_BLOB}")
    else
      assert_equal(private_blob, ppk.private_blob)
    end
  end

  [2, 3].each do |format|
    define_method("test_initialize_unencrypted_format_#{format}") do
      ppk = PuTTY::Key::PPK.new(fixture_path("test-format-#{format}.ppk"))
      assert_test_ppk_properties(ppk)
    end

    define_method("test_initialize_encrypted_format_#{format}") do
      ppk = PuTTY::Key::PPK.new(fixture_path("test-encrypted-format-#{format}.ppk"), 'Test Passphrase')
      assert_test_ppk_properties(ppk, encrypted: true)
    end

    define_method("test_initialize_encrypted_no_passphrase_#{format}") do
      path = fixture_path("test-encrypted-format-#{format}.ppk")
      assert_raises(ArgumentError) { PuTTY::Key::PPK.new(path) }
    end

    define_method("test_initialize_encrypted_incorrect_passphrase_#{format}") do
      path = fixture_path("test-encrypted-format-#{format}.ppk")
      assert_raises(ArgumentError) { PuTTY::Key::PPK.new(path, 'Not Test Passphrase') }
    end
  end

  # type-d and type-i fixtures also use different Argon2 parameters.
  [:d, :i].each do |type|
    define_method("test_initialize_encrypted_format_3_type_#{type}") do
      ppk = PuTTY::Key::PPK.new(fixture_path("test-encrypted-type-#{type}-format-3.ppk"), 'Test Passphrase')
      assert_test_ppk_properties(ppk, encrypted: true)
    end
  end

  def test_initialize_blank_comment
    ppk = PuTTY::Key::PPK.new(fixture_path('test-blank-comment.ppk'))
    assert_test_ppk_properties(ppk, comment: ''.b)
  end

  def test_initialize_empty_blobs
    ppk = PuTTY::Key::PPK.new(fixture_path('test-empty-blobs.ppk'))
    assert_test_ppk_properties(ppk, public_blob: ''.b, private_blob: ''.b, encrypted: true)
  end

  def test_initialize_empty_blobs_encrypted
    ppk = PuTTY::Key::PPK.new(fixture_path('test-empty-blobs-encrypted.ppk'), 'Test Passphrase')
    assert_test_ppk_properties(ppk, public_blob: ''.b, private_blob: ''.b, encrypted: true)
  end

  def test_initialize_missing_final_line_ending
    ppk = PuTTY::Key::PPK.new(fixture_path('test-missing-final-line-ending.ppk'))
    assert_test_ppk_properties(ppk)
  end

  def test_initialize_pathname
    ppk = PuTTY::Key::PPK.new(Pathname.new(fixture_path('test-format-2.ppk')))
    assert_test_ppk_properties(ppk)
  end

  def test_initialize_from_io_with_getbyte
    File.open(fixture_path('test-format-2.ppk'), 'rb') do |file|
      reader = TestReaderWithGetbyte.new(file)
      ppk = PuTTY::Key::PPK.new(reader)
      assert_test_ppk_properties(ppk)
    end
  end

  def test_initialize_from_io_with_read
    File.open(fixture_path('test-format-2.ppk'), 'rb') do |file|
      reader = TestReaderWithRead.new(file)
      ppk = PuTTY::Key::PPK.new(reader)
      assert_test_ppk_properties(ppk)
    end
  end

  def test_initialize_from_io_with_binmode
    File.open(fixture_path('test-format-2.ppk'), 'r') do |file|
      reader = TestReaderWithBinmode.new(file)
      ppk = PuTTY::Key::PPK.new(reader)
      assert_equal(1, reader.binmode_calls)
      assert_test_ppk_properties(ppk)
    end
  end

  %w(legacy_mac windows).each do |type|
    define_method("test_initialize_#{type}_line_endings") do
      ppk = PuTTY::Key::PPK.new(fixture_path("test-#{type.gsub('_', '-')}-line-endings.ppk"))
      assert_test_ppk_properties(ppk)
    end
  end

  def create_test_ppk
    PuTTY::Key::PPK.new.tap do |ppk|
      ppk.algorithm = 'test'
      ppk.comment = TEST_COMMENT
      ppk.public_blob = TEST_PUBLIC_BLOB
      ppk.private_blob = TEST_PRIVATE_BLOB
    end
  end

  def test_save_path_nil
    ppk = create_test_ppk
    assert_raises(ArgumentError) { ppk.save(nil) }
  end

  def test_save_passphrase_encryption_type_nil
    ppk = create_test_ppk
    temp_file_name do |file|
      assert_raises(ArgumentError) { ppk.save(file, 'Test Passphrase', encryption_type: nil) }
    end
  end

  def test_save_passphrase_encryption_type_none
    ppk = create_test_ppk
    temp_file_name do |file|
      assert_raises(ArgumentError) { ppk.save(file, 'Test Passphrase', encryption_type: 'none') }
    end
  end

  def test_save_passphrase_unsupported_encryption_type
    ppk = create_test_ppk
    temp_file_name do |file|
      assert_raises(ArgumentError) { ppk.save(file, 'Test Passphrase', encryption_type: 'camellia256-cbc') }
    end
  end

  def test_save_format_nil
    ppk = create_test_ppk
    temp_file_name do |file|
      assert_raises(ArgumentError) { ppk.save(file, 'Test Passphrase', format: nil) }
    end
  end

  [PuTTY::Key::PPK::MINIMUM_FORMAT - 1, PuTTY::Key::PPK::MAXIMUM_FORMAT + 1].each do |format|
    define_method("test_save_format_#{format}_not_supported") do
      ppk = create_test_ppk
      temp_file_name do |file|
        assert_raises(ArgumentError) { ppk.save(file, 'Test Passphrase', format: format) }
      end
    end
  end

  def test_save_dir_not_exists
    ppk = create_test_ppk
    temp_dir do |dir|
      assert_raises(Errno::ENOENT) { ppk.save(File.join(dir, 'missing', 'file')) }
    end
  end

  def test_save_algorithm_nil
    ppk = create_test_ppk
    ppk.algorithm = nil
    temp_file_name do |file|
      assert_raises(PuTTY::Key::InvalidStateError) { ppk.save(file) }
    end
  end

  def test_save_public_blob_nil
    ppk = create_test_ppk
    ppk.public_blob = nil
    temp_file_name do |file|
      assert_raises(PuTTY::Key::InvalidStateError) { ppk.save(file) }
    end
  end

  def test_save_private_blob_nil
    ppk = create_test_ppk
    ppk.private_blob = nil
    temp_file_name do |file|
      assert_raises(PuTTY::Key::InvalidStateError) { ppk.save(file) }
    end
  end

  [2, 3].each do |format|
    define_method("test_save_unencrypted_format_#{format}") do
      ppk = create_test_ppk
      temp_file_name do |file|
        ppk.save(file, format: format)
        assert_identical_to_fixture("test-format-#{format}.ppk", file)
      end
    end

    define_method("test_save_passphrase_empty_format_#{format}") do
      ppk = create_test_ppk
      temp_file_name do |file|
        ppk.save(file, '', format: format)
        assert_identical_to_fixture("test-format-#{format}.ppk", file)
      end
    end

    define_method("test_save_encrypted_format_#{format}") do
      ppk = create_test_ppk
      temp_file_name do |file|
        ppk.save(file, 'Test Passphrase', format: format, argon2_params: PuTTY::Key::Argon2Params.new(passes: 8, salt: "\x7d\x5d\x45\x57\xc5\x56\x3a\x5b\x50\x09\xe1\x45\x2c\x51\x8e\x04".b))
        assert_identical_to_fixture("test-encrypted-format-#{format}.ppk", file)
      end
    end
  end

  # type_d and type_i tests cover other Argon2 parameters too.
  def test_save_encrypted_type_d_format_3
    ppk = create_test_ppk
    temp_file_name do |file|
      ppk.save(file, 'Test Passphrase', format: 3, argon2_params: PuTTY::Key::Argon2Params.new(type: :d, memory: 4096, passes: 9, salt: "\xbc\x44\x19\x1a\xa9\x26\x73\xa5\xc0\x54\x3f\x37\x36\x33\xdd\xf4".b ))
      assert_identical_to_fixture("test-encrypted-type-d-format-3.ppk", file)
    end
  end

  def test_save_encrypted_type_i_format_3
    ppk = create_test_ppk
    temp_file_name do |file|
      ppk.save(file, 'Test Passphrase', format: 3, argon2_params: PuTTY::Key::Argon2Params.new(type: :i, memory: 2048, passes: 5, parallelism: 3, salt: "\xbd\x5e\x3d\x94\x03\xec\x37\x41\x8b\xa5\xae\x1d\x11\x6f\xa9\x75".b ))
      assert_identical_to_fixture("test-encrypted-type-i-format-3.ppk", file)
    end
  end

  def get_field(file, name)
    line = File.readlines(file, mode: 'rb').find {|l| l.start_with?("#{name}: ")}
    line && line.byteslice(name.bytesize + 2, line.bytesize - name.bytesize - 2).chomp("\n")
  end

  def test_save_chooses_random_salt
    ppk = create_test_ppk
    temp_file_name do |file|
      ppk.save(file, 'Test Passphrase', format: 3)
      salt1 = get_field(file, 'Argon2-Salt')
      assert_match(/\A[0-9a-f]{32}\z/, salt1)

      File.unlink(file)
      ppk.save(file, 'Test Passphrase', format: 3)
      salt2 = get_field(file, 'Argon2-Salt')
      assert_match(/\A[0-9a-f]{32}\z/, salt2)

      refute_equal(salt1, salt2)
    end
  end

  def test_save_calculates_passes_required_for_time
    ppk = create_test_ppk
    temp_file_name do |file|
      ppk.save(file, 'Test Passphrase', format: 3, argon2_params: PuTTY::Key::Argon2Params.new(desired_time: 0))
      passes = get_field(file, 'Argon2-Passes').to_i
      initial_passes = passes

      100.step(by: 100, to: 1000) do |desired_time|
        File.unlink(file)
        ppk.save(file, 'Test Passphrase', format: 3, argon2_params: PuTTY::Key::Argon2Params.new(desired_time: desired_time))
        passes = get_field(file, 'Argon2-Passes').to_i
        break if passes > initial_passes
      end

      assert(passes > initial_passes)
    end
  end

  def test_save_raises_error_if_libargon2_rejects_parameters
    ppk = create_test_ppk
    temp_file_name do |file|
      argon2_params = PuTTY::Key::Argon2Params.new(memory: 1)
      assert_raises(PuTTY::Key::Argon2Error) { ppk.save(file, 'Test Passphrase', format: 3, argon2_params: argon2_params) }
    end
  end

  def test_save_comment_empty
    ppk = create_test_ppk
    ppk.comment = ''
    temp_file_name do |file|
      ppk.save(file)
      assert_identical_to_fixture('test-blank-comment.ppk', file)
    end
  end

  def test_save_comment_nil
    ppk = create_test_ppk
    ppk.comment = nil
    temp_file_name do |file|
      ppk.save(file)
      assert_identical_to_fixture('test-blank-comment.ppk', file)
    end
  end

  def test_save_empty_blobs
    ppk = create_test_ppk
    ppk.public_blob = ''.b
    ppk.private_blob = ''.b
    temp_file_name do |file|
      ppk.save(file)
      assert_identical_to_fixture('test-empty-blobs.ppk', file)
    end
  end

  def test_save_empty_blobs_encrypted
    ppk = create_test_ppk
    ppk.public_blob = ''.b
    ppk.private_blob = ''.b
    temp_file_name do |file|
      ppk.save(file, 'Test Passphrase')
      assert_identical_to_fixture('test-empty-blobs-encrypted.ppk', file)
    end
  end

  def get_blob(file, name)
    lines = File.readlines(file, mode: 'rb')
    index = lines.find_index {|l| l.start_with?("#{name}-Lines: ")}
    return nil unless index
    line = lines[index]
    count = line.byteslice(name.bytesize + 8, line.bytesize - name.bytesize - 2).chomp("\n").to_i
    blob_lines = lines[index + 1, count]
    blob_lines.join("\n").unpack('m48').first
  end

  [[0, 0], [15, 1], [16, 0], [17, 15], [18, 14], [30, 2], [31, 1], [32, 0]].each do |length, needed|
    define_method("test_save_encrypted_pads_private_blob_of_length_#{length}_to_multiple_of_block_size_with_sha1") do
      private_blob = "\0".b * length
      ppk = create_test_ppk
      ppk.private_blob = private_blob

      temp_file_name do |file|
        ppk.save(file, 'Test Passphrase')
        encrypted_padded_private_blob = get_blob(file, 'Private')
        assert_equal(length + needed, encrypted_padded_private_blob.bytesize)
        assert_equal(private_blob, ppk.private_blob)

        loaded_ppk = PuTTY::Key::PPK.new(file, 'Test Passphrase')
        assert_equal(length + needed, loaded_ppk.private_blob.bytesize)

        if needed == 0
          assert_equal(private_blob, loaded_ppk.private_blob)
        else
          assert_equal(private_blob, loaded_ppk.private_blob.byteslice(0, length))
          padding = loaded_ppk.private_blob.byteslice(length, needed)
          expected_padding = OpenSSL::Digest::SHA1.new(private_blob).digest.byteslice(0, needed)
          assert_equal(expected_padding, padding)
        end
      end
    end
  end

  def test_save_pathname
    ppk = create_test_ppk
    temp_file_name do |file|
      ppk.save(Pathname.new(file))
      assert_identical_to_fixture('test-format-2.ppk', file)
    end
  end

  def test_save_to_io
    ppk = create_test_ppk
    temp_file_name do |file_name|
      File.open(file_name, 'wb') do |file|
        writer = TestWriter.new(file)
        ppk.save(writer)
      end
      assert_identical_to_fixture('test-format-2.ppk', file_name)
    end
  end

  def test_save_to_io_with_binmode
    ppk = create_test_ppk
    temp_file_name do |file_name|
      File.open(file_name, 'w') do |file|
        writer = TestWriterWithBinmode.new(file)
        ppk.save(writer)
        assert_equal(1, writer.binmode_calls)
      end
      assert_identical_to_fixture('test-format-2.ppk', file_name)
    end
  end

  def test_save_overwrite
    ppk = create_test_ppk
    temp_file_name do |file|
      File.open(file, 'w') { |f| f.write('not test.ppk') }
      ppk.save(file)
      assert_identical_to_fixture('test-format-2.ppk', file)
    end
  end

  def test_save_result
    ppk = create_test_ppk
    temp_file_name do |file|
      result = ppk.save(file)
      assert_equal(File.size(file), result)
    end
  end

  module BinmodeCallsTest
    def binmode
      if instance_variable_defined?(:@binmode_calls)
        @binmode_calls += 1
      else
        @binmode_calls = 1
      end
      @io.binmode
      self
    end

    def binmode_calls
      instance_variable_defined?(:@binmode_calls) ? @binmode_calls : 0
    end
  end

  class TestReaderWithGetbyte
    def initialize(io)
      @io = io
    end

    def getbyte(*args)
      @io.getbyte(*args)
    end
  end

  class TestReaderWithRead
    def initialize(io)
      @io = io
    end

    def read(*args)
      @io.read(*args)
    end
  end

  class TestReaderWithBinmode < TestReaderWithGetbyte
    include BinmodeCallsTest

    def getbyte(*args)
      raise 'binmode must be called before getbyte' unless binmode_calls > 0
      super
    end
  end

  class TestWriter
    def initialize(io)
      @io = io
    end

    def write(*args)
      @io.write(*args)
    end
  end

  class TestWriterWithBinmode < TestWriter
    include BinmodeCallsTest

    def write(*args)
      raise 'binmode must be called before write' unless binmode_calls > 0
      super
    end
  end
end
