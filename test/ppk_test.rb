require 'test_helper'
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

  def test_initialize_invalid_format
    [1,3].each do |format|
      assert_raises(PuTTY::Key::FormatError) { PuTTY::Key::PPK.new(fixture_path("test-invalid-format-#{format}.ppk")) }
    end
  end

  def test_initialize_invalid_encryption_type
    assert_raises(PuTTY::Key::FormatError) { PuTTY::Key::PPK.new(fixture_path('test-invalid-encryption-type.ppk')) }
  end

  def test_initialize_invalid_private_mac
    assert_raises(PuTTY::Key::FormatError) { PuTTY::Key::PPK.new(fixture_path('test-invalid-private-mac.ppk')) }
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

  def test_initialize_invalid_blob_lines
    assert_raises(PuTTY::Key::FormatError) { PuTTY::Key::PPK.new(fixture_path('test-invalid-blob-lines.ppk')) }
  end

  def assert_test_ppk_properties(ppk, comment: TEST_COMMENT, encrypted: false)
    assert_equal(Encoding::ASCII_8BIT, ppk.algorithm.encoding)
    assert_equal(Encoding::ASCII_8BIT, ppk.comment.encoding)
    assert_equal(Encoding::ASCII_8BIT, ppk.public_blob.encoding)
    assert_equal(Encoding::ASCII_8BIT, ppk.private_blob.encoding)
    assert_equal('test'.b, ppk.algorithm)
    assert_equal(comment, ppk.comment)
    assert_equal(TEST_PUBLIC_BLOB, ppk.public_blob)

    if encrypted
      # When loading an encrypted ppk file, the padding added to the private blob cannot be removed.
      assert(ppk.private_blob.start_with?(TEST_PRIVATE_BLOB), "Private blob does not start with #{TEST_PRIVATE_BLOB}")
    else
      assert_equal(TEST_PRIVATE_BLOB, ppk.private_blob)
    end
  end

  def test_initialize_unencrypted
    ppk = PuTTY::Key::PPK.new(fixture_path('test.ppk'))
    assert_test_ppk_properties(ppk)
  end

  def test_initialize_blank_comment
    ppk = PuTTY::Key::PPK.new(fixture_path('test-blank-comment.ppk'))
    assert_test_ppk_properties(ppk, comment: ''.b)
  end

  def test_initialize_encrypted
    ppk = PuTTY::Key::PPK.new(fixture_path('test-encrypted.ppk'), 'Test Passphrase')
    assert_test_ppk_properties(ppk, encrypted: true)
  end

  def test_initialize_encrypted_no_passphrase
    assert_raises(ArgumentError) { PuTTY::Key::PPK.new(fixture_path('test-encrypted.ppk')) }
  end

  def test_initialize_encrypted_incorrect_passphrase
    assert_raises(ArgumentError) { PuTTY::Key::PPK.new(fixture_path('test-encrypted.ppk'), 'Not Test Passphrase') }
  end

  def test_initialize_pathname
    ppk = PuTTY::Key::PPK.new(Pathname.new(fixture_path('test.ppk')))
    assert_test_ppk_properties(ppk)
  end

  def test_initialize_unix_line_endings
    ppk = PuTTY::Key::PPK.new(fixture_path('test-unix-line-endings.ppk'))
    assert_test_ppk_properties(ppk)
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

  def test_save_format_not_supported
    ppk = create_test_ppk
    temp_file_name do |file|
      [1,3].each do |format|
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

  def test_save_unencrypted
    ppk = create_test_ppk
    temp_file_name do |file|
      ppk.save(file)
      assert_identical_to_fixture('test.ppk', file)
    end
  end

  def test_save_passphrase_empty
    ppk = create_test_ppk
    temp_file_name do |file|
      ppk.save(file, '')
      assert_identical_to_fixture('test.ppk', file)
    end
  end

  def test_save_encrypted
    ppk = create_test_ppk
    temp_file_name do |file|
      ppk.save(file, 'Test Passphrase')
      assert_identical_to_fixture('test-encrypted.ppk', file)
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

  def test_save_pathname
    ppk = create_test_ppk
    temp_file_name do |file|
      ppk.save(Pathname.new(file))
      assert_identical_to_fixture('test.ppk', file)
    end
  end

  def test_save_overwrite
    ppk = create_test_ppk
    temp_file_name do |file|
      File.open(file, 'w') { |f| f.write('not test.ppk') }
      ppk.save(file)
      assert_identical_to_fixture('test.ppk', file)
    end
  end

  def test_save_result
    ppk = create_test_ppk
    temp_file_name do |file|
      result = ppk.save(file)
      assert_equal(File.size(file), result)
    end
  end
end
