# frozen_string_literal: true

require_relative 'test_helper'

if TEST_TYPE == :refinement
  using PuTTY::Key
end

class OpenSSLTest < Minitest::Test
  def test_from_ppk_nil
    assert_raises(ArgumentError) { OpenSSL::PKey.from_ppk(nil) }
  end

  def test_from_ppk_unsupported_algorithm
    ppk = PuTTY::Key::PPK.new(fixture_path('test-format-2.ppk'))
    assert_raises(ArgumentError) { OpenSSL::PKey.from_ppk(ppk) }
  end

  def test_from_ppk_rsa_format_2
    ppk = PuTTY::Key::PPK.new(fixture_path('rsa-2048-format-2.ppk'))
    pkey = OpenSSL::PKey.from_ppk(ppk)
    assert_kind_of(OpenSSL::PKey::RSA, pkey)
    assert_equal(normalize_pem_fixture('rsa-2048.pem'), pkey.to_pem)
  end

  def test_from_ppk_rsa_encrypted_format_2
    ppk = PuTTY::Key::PPK.new(fixture_path('rsa-2048-encrypted-format-2.ppk'), 'Test Passphrase')
    pkey = OpenSSL::PKey.from_ppk(ppk)
    assert_kind_of(OpenSSL::PKey::RSA, pkey)
    assert_equal(normalize_pem_fixture('rsa-2048.pem'), pkey.to_pem)
  end

  def test_from_ppk_rsa_format_3
    ppk = PuTTY::Key::PPK.new(fixture_path('rsa-2048-format-3.ppk'))
    pkey = OpenSSL::PKey.from_ppk(ppk)
    assert_kind_of(OpenSSL::PKey::RSA, pkey)
    assert_equal(normalize_pem_fixture('rsa-2048.pem'), pkey.to_pem)
  end

  def test_from_ppk_rsa_encrypted_format_3
    ppk = PuTTY::Key::PPK.new(fixture_path('rsa-2048-encrypted-format-3.ppk'), 'Test Passphrase')
    pkey = OpenSSL::PKey.from_ppk(ppk)
    assert_kind_of(OpenSSL::PKey::RSA, pkey)
    assert_equal(normalize_pem_fixture('rsa-2048.pem'), pkey.to_pem)
  end

  def test_from_ppk_dss_format_2
    ppk = PuTTY::Key::PPK.new(fixture_path('dss-1024-format-2.ppk'))
    pkey = OpenSSL::PKey.from_ppk(ppk)
    assert_kind_of(OpenSSL::PKey::DSA, pkey)
    assert_equal(normalize_pem_fixture('dss-1024.pem'), pkey.to_pem)
  end

  def test_from_ppk_dss_encrypted_format_2
    ppk = PuTTY::Key::PPK.new(fixture_path('dss-1024-encrypted-format-2.ppk'), 'Test Passphrase')
    pkey = OpenSSL::PKey.from_ppk(ppk)
    assert_kind_of(OpenSSL::PKey::DSA, pkey)
    assert_equal(normalize_pem_fixture('dss-1024.pem'), pkey.to_pem)
  end

  def test_from_ppk_dss_format_3
    ppk = PuTTY::Key::PPK.new(fixture_path('dss-1024-format-3.ppk'))
    pkey = OpenSSL::PKey.from_ppk(ppk)
    assert_kind_of(OpenSSL::PKey::DSA, pkey)
    assert_equal(normalize_pem_fixture('dss-1024.pem'), pkey.to_pem)
  end

  def test_from_ppk_dss_encrypted_format_3
    ppk = PuTTY::Key::PPK.new(fixture_path('dss-1024-encrypted-format-3.ppk'), 'Test Passphrase')
    pkey = OpenSSL::PKey.from_ppk(ppk)
    assert_kind_of(OpenSSL::PKey::DSA, pkey)
    assert_equal(normalize_pem_fixture('dss-1024.pem'), pkey.to_pem)
  end

  # Old versions of jruby-openssl don't include an EC class (version 0.9.16).
  if defined?(OpenSSL::PKey::EC)
    def test_from_ppk_ecdsa_sha2_nistp256_format_2
      ppk = PuTTY::Key::PPK.new(fixture_path('ecdsa-sha2-nistp256-format-2.ppk'))
      pkey = OpenSSL::PKey.from_ppk(ppk)
      assert_kind_of(OpenSSL::PKey::EC, pkey)
      assert_equal(normalize_pem_fixture('ecdsa-sha2-nistp256.pem', OpenSSL::PKey::EC), pkey.to_pem)
    end

    def test_from_ppk_ecdsa_sha2_nistp256_encrypted_format_2
      ppk = PuTTY::Key::PPK.new(fixture_path('ecdsa-sha2-nistp256-encrypted-format-2.ppk'), 'Test Passphrase')
      pkey = OpenSSL::PKey.from_ppk(ppk)
      assert_kind_of(OpenSSL::PKey::EC, pkey)
      assert_equal(normalize_pem_fixture('ecdsa-sha2-nistp256.pem', OpenSSL::PKey::EC), pkey.to_pem)
    end

    def test_from_ppk_ecdsa_sha2_nistp256_format_3
      ppk = PuTTY::Key::PPK.new(fixture_path('ecdsa-sha2-nistp256-format-3.ppk'))
      pkey = OpenSSL::PKey.from_ppk(ppk)
      assert_kind_of(OpenSSL::PKey::EC, pkey)
      assert_equal(normalize_pem_fixture('ecdsa-sha2-nistp256.pem', OpenSSL::PKey::EC), pkey.to_pem)
    end

    def test_from_ppk_ecdsa_sha2_nistp256_encrypted_format_3
      ppk = PuTTY::Key::PPK.new(fixture_path('ecdsa-sha2-nistp256-encrypted-format-3.ppk'), 'Test Passphrase')
      pkey = OpenSSL::PKey.from_ppk(ppk)
      assert_kind_of(OpenSSL::PKey::EC, pkey)
      assert_equal(normalize_pem_fixture('ecdsa-sha2-nistp256.pem', OpenSSL::PKey::EC), pkey.to_pem)
    end

    def test_from_ppk_ecdsa_sha2_nistp384_format_2
      ppk = PuTTY::Key::PPK.new(fixture_path('ecdsa-sha2-nistp384-format-2.ppk'))
      pkey = OpenSSL::PKey.from_ppk(ppk)
      assert_kind_of(OpenSSL::PKey::EC, pkey)
      assert_equal(normalize_pem_fixture('ecdsa-sha2-nistp384.pem', OpenSSL::PKey::EC), pkey.to_pem)
    end

    def test_from_ppk_ecdsa_sha2_nistp384_encrypted_format_2
      ppk = PuTTY::Key::PPK.new(fixture_path('ecdsa-sha2-nistp384-encrypted-format-2.ppk'), 'Test Passphrase')
      pkey = OpenSSL::PKey.from_ppk(ppk)
      assert_kind_of(OpenSSL::PKey::EC, pkey)
      assert_equal(normalize_pem_fixture('ecdsa-sha2-nistp384.pem', OpenSSL::PKey::EC), pkey.to_pem)
    end

    def test_from_ppk_ecdsa_sha2_nistp384_format_3
      ppk = PuTTY::Key::PPK.new(fixture_path('ecdsa-sha2-nistp384-format-3.ppk'))
      pkey = OpenSSL::PKey.from_ppk(ppk)
      assert_kind_of(OpenSSL::PKey::EC, pkey)
      assert_equal(normalize_pem_fixture('ecdsa-sha2-nistp384.pem', OpenSSL::PKey::EC), pkey.to_pem)
    end

    def test_from_ppk_ecdsa_sha2_nistp384_encrypted_format_3
      ppk = PuTTY::Key::PPK.new(fixture_path('ecdsa-sha2-nistp384-encrypted-format-3.ppk'), 'Test Passphrase')
      pkey = OpenSSL::PKey.from_ppk(ppk)
      assert_kind_of(OpenSSL::PKey::EC, pkey)
      assert_equal(normalize_pem_fixture('ecdsa-sha2-nistp384.pem', OpenSSL::PKey::EC), pkey.to_pem)
    end

    def test_from_ppk_ecdsa_sha2_nistp521_format_2
      ppk = PuTTY::Key::PPK.new(fixture_path('ecdsa-sha2-nistp521-format-2.ppk'))
      pkey = OpenSSL::PKey.from_ppk(ppk)
      assert_kind_of(OpenSSL::PKey::EC, pkey)
      assert_equal(normalize_pem_fixture('ecdsa-sha2-nistp521.pem', OpenSSL::PKey::EC), pkey.to_pem)
    end

    def test_from_ppk_ecdsa_sha2_nistp521_encrypted_format_2
      ppk = PuTTY::Key::PPK.new(fixture_path('ecdsa-sha2-nistp521-encrypted-format-2.ppk'), 'Test Passphrase')
      pkey = OpenSSL::PKey.from_ppk(ppk)
      assert_kind_of(OpenSSL::PKey::EC, pkey)
      assert_equal(normalize_pem_fixture('ecdsa-sha2-nistp521.pem', OpenSSL::PKey::EC), pkey.to_pem)
    end

    def test_from_ppk_ecdsa_sha2_nistp521_format_3
      ppk = PuTTY::Key::PPK.new(fixture_path('ecdsa-sha2-nistp521-format-3.ppk'))
      pkey = OpenSSL::PKey.from_ppk(ppk)
      assert_kind_of(OpenSSL::PKey::EC, pkey)
      assert_equal(normalize_pem_fixture('ecdsa-sha2-nistp521.pem', OpenSSL::PKey::EC), pkey.to_pem)
    end

    def test_from_ppk_ecdsa_sha2_nistp521_encrypted_format_3
      ppk = PuTTY::Key::PPK.new(fixture_path('ecdsa-sha2-nistp521-encrypted-format-3.ppk'), 'Test Passphrase')
      pkey = OpenSSL::PKey.from_ppk(ppk)
      assert_kind_of(OpenSSL::PKey::EC, pkey)
      assert_equal(normalize_pem_fixture('ecdsa-sha2-nistp521.pem', OpenSSL::PKey::EC), pkey.to_pem)
    end
  else
    def test_from_ppk_ecdsa_sha2_nistp256_format_2
      ppk = PuTTY::Key::PPK.new(fixture_path('ecdsa-sha2-nistp256-format-2.ppk'))
      assert_raises(ArgumentError) { OpenSSL::PKey.from_ppk(ppk) }
    end

    def test_from_ppk_ecdsa_sha2_nistp256_encrypted_format_2
      ppk = PuTTY::Key::PPK.new(fixture_path('ecdsa-sha2-nistp256-encrypted-format-2.ppk'), 'Test Passphrase')
      assert_raises(ArgumentError) { OpenSSL::PKey.from_ppk(ppk) }
    end

    def test_from_ppk_ecdsa_sha2_nistp256_format_3
      ppk = PuTTY::Key::PPK.new(fixture_path('ecdsa-sha2-nistp256-format-3.ppk'))
      assert_raises(ArgumentError) { OpenSSL::PKey.from_ppk(ppk) }
    end

    def test_from_ppk_ecdsa_sha2_nistp256_encrypted_format_3
      ppk = PuTTY::Key::PPK.new(fixture_path('ecdsa-sha2-nistp256-encrypted-format-3.ppk'), 'Test Passphrase')
      assert_raises(ArgumentError) { OpenSSL::PKey.from_ppk(ppk) }
    end

    def test_from_ppk_ecdsa_sha2_nistp384_format_2
      ppk = PuTTY::Key::PPK.new(fixture_path('ecdsa-sha2-nistp384-format-2.ppk'))
      assert_raises(ArgumentError) { OpenSSL::PKey.from_ppk(ppk) }
    end

    def test_from_ppk_ecdsa_sha2_nistp384_encrypted_format_2
      ppk = PuTTY::Key::PPK.new(fixture_path('ecdsa-sha2-nistp384-encrypted-format-2.ppk'), 'Test Passphrase')
      assert_raises(ArgumentError) { OpenSSL::PKey.from_ppk(ppk) }
    end

    def test_from_ppk_ecdsa_sha2_nistp384_format_3
      ppk = PuTTY::Key::PPK.new(fixture_path('ecdsa-sha2-nistp384-format-3.ppk'))
      assert_raises(ArgumentError) { OpenSSL::PKey.from_ppk(ppk) }
    end

    def test_from_ppk_ecdsa_sha2_nistp384_encrypted_format_3
      ppk = PuTTY::Key::PPK.new(fixture_path('ecdsa-sha2-nistp384-encrypted-format-3.ppk'), 'Test Passphrase')
      assert_raises(ArgumentError) { OpenSSL::PKey.from_ppk(ppk) }
    end

    def test_from_ppk_ecdsa_sha2_nistp521_format_2
      ppk = PuTTY::Key::PPK.new(fixture_path('ecdsa-sha2-nistp521-format-2.ppk'))
      assert_raises(ArgumentError) { OpenSSL::PKey.from_ppk(ppk) }
    end

    def test_from_ppk_ecdsa_sha2_nistp521_encrypted_format_2
      ppk = PuTTY::Key::PPK.new(fixture_path('ecdsa-sha2-nistp521-encrypted-format-2.ppk'), 'Test Passphrase')
      assert_raises(ArgumentError) { OpenSSL::PKey.from_ppk(ppk) }
    end

    def test_from_ppk_ecdsa_sha2_nistp521_format_3
      ppk = PuTTY::Key::PPK.new(fixture_path('ecdsa-sha2-nistp521-format-3.ppk'))
      assert_raises(ArgumentError) { OpenSSL::PKey.from_ppk(ppk) }
    end

    def test_from_ppk_ecdsa_sha2_nistp521_encrypted_format_3
      ppk = PuTTY::Key::PPK.new(fixture_path('ecdsa-sha2-nistp521-encrypted-format-3.ppk'), 'Test Passphrase')
      assert_raises(ArgumentError) { OpenSSL::PKey.from_ppk(ppk) }
    end
  end

  def load_key(fixture, type = nil)
    pem = load_fixture(fixture)

    # Accessing OpenSSL::PKey::EC#public_key raises a warning when the key was
    # loaded with OpenSSL::PKey.read(pem), but doesn't when instantiated with
    # OpenSSL::PKey::EC.new(pem) (Ruby 2.3.0).
    type ? type.new(pem) : OpenSSL::PKey.read(pem)
  end

  def pem_to_ppk(fixture, type = nil)
    pkey = load_key(fixture, type)

    pkey.to_ppk.tap do |ppk|
      assert_nil(ppk.comment)
    end
  end

  def normalize_pem_fixture(fixture, type = nil)
    pkey = load_key(fixture, type)
    pkey.to_pem
  end

  def test_to_ppk_rsa_format_2
    ppk = pem_to_ppk('rsa-2048.pem')
    ppk.comment = '2048 bit RSA key'
    temp_file_name do |file|
      ppk.save(file)
      assert_identical_to_fixture('rsa-2048-format-2.ppk', file)
    end
  end

  def test_to_ppk_rsa_encrypted_format_2
    ppk = pem_to_ppk('rsa-2048.pem')
    ppk.comment = '2048 bit RSA key'
    temp_file_name do |file|
      ppk.save(file, 'Test Passphrase')
      assert_identical_to_fixture('rsa-2048-encrypted-format-2.ppk', file)
    end
  end

  def test_to_ppk_rsa_format_3
    ppk = pem_to_ppk('rsa-2048.pem')
    ppk.comment = '2048 bit RSA key'
    temp_file_name do |file|
      ppk.save(file, format: 3)
      assert_identical_to_fixture('rsa-2048-format-3.ppk', file)
    end
  end

  def test_to_ppk_rsa_encrypted_format_3
    ppk = pem_to_ppk('rsa-2048.pem')
    ppk.comment = '2048 bit RSA key'
    temp_file_name do |file|
      ppk.save(file, 'Test Passphrase', format: 3, argon2_params: PuTTY::Key::Argon2Params.new(memory: 16384, parallelism: 2, passes: 14, salt: "\xcc\x2e\xc7\x12\xee\x7e\x17\xbc\x2b\x9e\x3c\x47\xf5\xbb\xb0\x66".b))
      assert_identical_to_fixture('rsa-2048-encrypted-format-3.ppk', file)
    end
  end

  def test_to_ppk_rsa_uninitialized
    pkey = begin
      OpenSSL::PKey::RSA.new
    rescue ArgumentError
      skip('OpenSSL::PKey::RSA cannot be created in an uninitialized state')
    end
    assert_raises(PuTTY::Key::InvalidStateError) { pkey.to_ppk }
  end

  def test_to_ppk_dss_format_2
    ppk = pem_to_ppk('dss-1024.pem')
    ppk.comment = '1024 bit DSS key'
    temp_file_name do |file|
      ppk.save(file)
      assert_identical_to_fixture('dss-1024-format-2.ppk', file)
    end
  end

  def test_to_ppk_dss_encrypted_format_2
    ppk = pem_to_ppk('dss-1024.pem')
    ppk.comment = '1024 bit DSS key'
    temp_file_name do |file|
      ppk.save(file, 'Test Passphrase')
      assert_identical_to_fixture('dss-1024-encrypted-format-2.ppk', file)
    end
  end

  def test_to_ppk_dss_format_3
    ppk = pem_to_ppk('dss-1024.pem')
    ppk.comment = '1024 bit DSS key'
    temp_file_name do |file|
      ppk.save(file, format: 3)
      assert_identical_to_fixture('dss-1024-format-3.ppk', file)
    end
  end

  def test_to_ppk_dss_encrypted_format_3
    ppk = pem_to_ppk('dss-1024.pem')
    ppk.comment = '1024 bit DSS key'
    temp_file_name do |file|
      ppk.save(file, 'Test Passphrase', format: 3, argon2_params: PuTTY::Key::Argon2Params.new(passes: 13, salt: "\x1a\x21\x57\x42\xbf\x63\xed\x4e\xef\xed\x21\xdd\x07\x68\x36\x40".b))
      assert_identical_to_fixture('dss-1024-encrypted-format-3.ppk', file)
    end
  end

  def test_to_ppk_dss_uninitialized
    pkey = begin
      OpenSSL::PKey::DSA.new
    rescue ArgumentError
      skip('OpenSSL::PKey::DSA cannot be created in an uninitialized state')
    end

    assert_raises(PuTTY::Key::InvalidStateError) { pkey.to_ppk }
  end

  # Old versions of jruby-openssl don't include an EC class (version 0.9.16).
  if defined?(OpenSSL::PKey::EC)
    def test_to_ppk_ecdsa_sha2_nistp256_format_2
      ppk = pem_to_ppk('ecdsa-sha2-nistp256.pem', OpenSSL::PKey::EC)
      ppk.comment = 'ECDSA NIST P-256 Key'
      temp_file_name do |file|
        ppk.save(file)
        assert_identical_to_fixture('ecdsa-sha2-nistp256-format-2.ppk', file)
      end
    end

    def test_to_ppk_ecdsa_sha2_nistp256_encrypted_format_2
      ppk = pem_to_ppk('ecdsa-sha2-nistp256.pem', OpenSSL::PKey::EC)
      ppk.comment = 'ECDSA NIST P-256 Key'
      temp_file_name do |file|
        ppk.save(file, 'Test Passphrase')
        assert_identical_to_fixture('ecdsa-sha2-nistp256-encrypted-format-2.ppk', file)
      end
    end

    def test_to_ppk_ecdsa_sha2_nistp256_format_3
      ppk = pem_to_ppk('ecdsa-sha2-nistp256.pem', OpenSSL::PKey::EC)
      ppk.comment = 'ECDSA NIST P-256 Key'
      temp_file_name do |file|
        ppk.save(file, format: 3)
        assert_identical_to_fixture('ecdsa-sha2-nistp256-format-3.ppk', file)
      end
    end

    def test_to_ppk_ecdsa_sha2_nistp256_encrypted_format_3
      ppk = pem_to_ppk('ecdsa-sha2-nistp256.pem', OpenSSL::PKey::EC)
      ppk.comment = 'ECDSA NIST P-256 Key'
      temp_file_name do |file|
        ppk.save(file, 'Test Passphrase', format: 3, argon2_params: PuTTY::Key::Argon2Params.new(type: :i, memory: 4096, passes: 12, salt: "\xba\x83\x64\xf0\xda\x7d\x81\x33\xbb\xd5\xf7\x39\x6a\xc2\x80\xf8".b))
        assert_identical_to_fixture('ecdsa-sha2-nistp256-encrypted-format-3.ppk', file)
      end
    end

    def test_to_ppk_ecdsa_sha2_nistp384_format_2
      ppk = pem_to_ppk('ecdsa-sha2-nistp384.pem', OpenSSL::PKey::EC)
      ppk.comment = 'ECDSA NIST P-384 Key'
      temp_file_name do |file|
        ppk.save(file)
        assert_identical_to_fixture('ecdsa-sha2-nistp384-format-2.ppk', file)
      end
    end

    def test_to_ppk_ecdsa_sha2_nistp384_encrypted_format_2
      ppk = pem_to_ppk('ecdsa-sha2-nistp384.pem', OpenSSL::PKey::EC)
      ppk.comment = 'ECDSA NIST P-384 Key'
      temp_file_name do |file|
        ppk.save(file, 'Test Passphrase')
        assert_identical_to_fixture('ecdsa-sha2-nistp384-encrypted-format-2.ppk', file)
      end
    end

    def test_to_ppk_ecdsa_sha2_nistp384_format_3
      ppk = pem_to_ppk('ecdsa-sha2-nistp384.pem', OpenSSL::PKey::EC)
      ppk.comment = 'ECDSA NIST P-384 Key'
      temp_file_name do |file|
        ppk.save(file, format: 3)
        assert_identical_to_fixture('ecdsa-sha2-nistp384-format-3.ppk', file)
      end
    end

    def test_to_ppk_ecdsa_sha2_nistp384_encrypted_format_3
      ppk = pem_to_ppk('ecdsa-sha2-nistp384.pem', OpenSSL::PKey::EC)
      ppk.comment = 'ECDSA NIST P-384 Key'
      temp_file_name do |file|
        ppk.save(file, 'Test Passphrase', format: 3, argon2_params: PuTTY::Key::Argon2Params.new(type: :i, parallelism: 2, passes: 6, salt: "\x0e\xe1\x39\x3b\x17\xb1\xc6\xa7\x79\x2f\x13\xcb\x80\x5e\x49\x56".b))
        assert_identical_to_fixture('ecdsa-sha2-nistp384-encrypted-format-3.ppk', file)
      end
    end

    def test_to_ppk_ecdsa_sha2_nistp521_format_2
      ppk = pem_to_ppk('ecdsa-sha2-nistp521.pem', OpenSSL::PKey::EC)
      ppk.comment = 'ECDSA NIST P-521 Key'
      temp_file_name do |file|
        ppk.save(file)
        assert_identical_to_fixture('ecdsa-sha2-nistp521-format-2.ppk', file)
      end
    end

    def test_to_ppk_ecdsa_sha2_nistp521_encrypted_format_2
      ppk = pem_to_ppk('ecdsa-sha2-nistp521.pem', OpenSSL::PKey::EC)
      ppk.comment = 'ECDSA NIST P-521 Key'
      temp_file_name do |file|
        ppk.save(file, 'Test Passphrase')
        assert_identical_to_fixture('ecdsa-sha2-nistp521-encrypted-format-2.ppk', file)
      end
    end

    def test_to_ppk_ecdsa_sha2_nistp521_format_3
      ppk = pem_to_ppk('ecdsa-sha2-nistp521.pem', OpenSSL::PKey::EC)
      ppk.comment = 'ECDSA NIST P-521 Key'
      temp_file_name do |file|
        ppk.save(file, format: 3)
        assert_identical_to_fixture('ecdsa-sha2-nistp521-format-3.ppk', file)
      end
    end

    def test_to_ppk_ecdsa_sha2_nistp521_encrypted_format_3
      ppk = pem_to_ppk('ecdsa-sha2-nistp521.pem', OpenSSL::PKey::EC)
      ppk.comment = 'ECDSA NIST P-521 Key'
      temp_file_name do |file|
        ppk.save(file, 'Test Passphrase', format: 3, argon2_params: PuTTY::Key::Argon2Params.new(type: :d, memory: 9220, passes: 13, salt: "\xea\x6c\x6e\xae\x1e\x22\xcb\x94\x49\xf8\x5c\x96\x57\xc2\x91\x57".b))
        assert_identical_to_fixture('ecdsa-sha2-nistp521-encrypted-format-3.ppk', file)
      end
    end

    def test_to_ppk_unsupported_ec_curve
      pkey = OpenSSL::PKey::EC.new(load_fixture('ecdsa-secp256k1.pem'))
      assert_raises(PuTTY::Key::UnsupportedCurveError) { pkey.to_ppk }
    end

    def test_to_ppk_uninitialized_ec_key
      pkey = OpenSSL::PKey::EC.new('prime256v1')
      assert_raises(PuTTY::Key::InvalidStateError) { pkey.to_ppk }
    end

    def test_to_ppk_uninitialized_ec_key_no_curve
      pkey = begin
        OpenSSL::PKey::EC.new
      rescue ArgumentError
        skip('OpenSSL::PKey::EC cannot be created in an uninitialized state')
      end
      assert_raises(PuTTY::Key::InvalidStateError) { pkey.to_ppk }
    end
  end
end
