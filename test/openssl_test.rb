require 'test_helper'

if TEST_TYPE == :refinement
  # JRuby 9.0.5.0 ignores the conditional and imports the refinements
  # regardless. Use send to prevent this.
  send(:using, PuTTY::Key)
end

class OpenSSLTest < Minitest::Test
  def test_from_ppk_nil
    assert_raises(ArgumentError) { OpenSSL::PKey.from_ppk(nil) }
  end

  def test_from_ppk_unsupported_algorithm
    ppk = PuTTY::Key::PPK.new(fixture_path('test.ppk'))
    assert_raises(ArgumentError) { OpenSSL::PKey.from_ppk(ppk) }
  end

  def test_from_ppk_rsa
    ppk = PuTTY::Key::PPK.new(fixture_path('rsa-2048.ppk'))
    pkey = OpenSSL::PKey.from_ppk(ppk)
    assert_kind_of(OpenSSL::PKey::RSA, pkey)
    assert_equal(load_fixture('rsa-2048.pem'), pkey.to_pem)
  end

  def test_from_ppk_rsa_encrypted
    ppk = PuTTY::Key::PPK.new(fixture_path('rsa-2048-encrypted.ppk'), 'Test Passphrase')
    pkey = OpenSSL::PKey.from_ppk(ppk)
    assert_kind_of(OpenSSL::PKey::RSA, pkey)
    assert_equal(load_fixture('rsa-2048.pem'), pkey.to_pem)
  end

  def test_from_ppk_dss
    ppk = PuTTY::Key::PPK.new(fixture_path('dss-1024.ppk'))
    pkey = OpenSSL::PKey.from_ppk(ppk)
    assert_kind_of(OpenSSL::PKey::DSA, pkey)
    assert_equal(load_fixture('dss-1024.pem'), pkey.to_pem)
  end

  def test_from_ppk_dss_encrypted
    ppk = PuTTY::Key::PPK.new(fixture_path('dss-1024-encrypted.ppk'), 'Test Passphrase')
    pkey = OpenSSL::PKey.from_ppk(ppk)
    assert_kind_of(OpenSSL::PKey::DSA, pkey)
    assert_equal(load_fixture('dss-1024.pem'), pkey.to_pem)
  end

  # jruby-openssl doesn't include an EC class (version 0.9.16)
  if defined?(OpenSSL::PKey::EC)
    def test_from_ppk_ecdsa_sha2_nistp256
      ppk = PuTTY::Key::PPK.new(fixture_path('ecdsa-sha2-nistp256.ppk'))
      pkey = OpenSSL::PKey.from_ppk(ppk)
      assert_kind_of(OpenSSL::PKey::EC, pkey)
      assert_equal(load_fixture('ecdsa-sha2-nistp256.pem'), pkey.to_pem)
    end

    def test_from_ppk_ecdsa_sha2_nistp256_encrypted
      ppk = PuTTY::Key::PPK.new(fixture_path('ecdsa-sha2-nistp256-encrypted.ppk'), 'Test Passphrase')
      pkey = OpenSSL::PKey.from_ppk(ppk)
      assert_kind_of(OpenSSL::PKey::EC, pkey)
      assert_equal(load_fixture('ecdsa-sha2-nistp256.pem'), pkey.to_pem)
    end

    def test_from_ppk_ecdsa_sha2_nistp384
      ppk = PuTTY::Key::PPK.new(fixture_path('ecdsa-sha2-nistp384.ppk'))
      pkey = OpenSSL::PKey.from_ppk(ppk)
      assert_kind_of(OpenSSL::PKey::EC, pkey)
      assert_equal(load_fixture('ecdsa-sha2-nistp384.pem'), pkey.to_pem)
    end

    def test_from_ppk_ecdsa_sha2_nistp384_encrypted
      ppk = PuTTY::Key::PPK.new(fixture_path('ecdsa-sha2-nistp384-encrypted.ppk'), 'Test Passphrase')
      pkey = OpenSSL::PKey.from_ppk(ppk)
      assert_kind_of(OpenSSL::PKey::EC, pkey)
      assert_equal(load_fixture('ecdsa-sha2-nistp384.pem'), pkey.to_pem)
    end

    def test_from_ppk_ecdsa_sha2_nistp521
      ppk = PuTTY::Key::PPK.new(fixture_path('ecdsa-sha2-nistp521.ppk'))
      pkey = OpenSSL::PKey.from_ppk(ppk)
      assert_kind_of(OpenSSL::PKey::EC, pkey)
      assert_equal(load_fixture('ecdsa-sha2-nistp521.pem'), pkey.to_pem)
    end

    def test_from_ppk_ecdsa_sha2_nistp521_encrypted
      ppk = PuTTY::Key::PPK.new(fixture_path('ecdsa-sha2-nistp521-encrypted.ppk'), 'Test Passphrase')
      pkey = OpenSSL::PKey.from_ppk(ppk)
      assert_kind_of(OpenSSL::PKey::EC, pkey)
      assert_equal(load_fixture('ecdsa-sha2-nistp521.pem'), pkey.to_pem)
    end
  else
    def test_from_ppk_ecdsa_sha2_nistp256
      ppk = PuTTY::Key::PPK.new(fixture_path('ecdsa-sha2-nistp256.ppk'))
      assert_raises(ArgumentError) { OpenSSL::PKey.from_ppk(ppk) }
    end

    def test_from_ppk_ecdsa_sha2_nistp256_encrypted
      ppk = PuTTY::Key::PPK.new(fixture_path('ecdsa-sha2-nistp256-encrypted.ppk'), 'Test Passphrase')
      assert_raises(ArgumentError) { OpenSSL::PKey.from_ppk(ppk) }
    end

    def test_from_ppk_ecdsa_sha2_nistp384
      ppk = PuTTY::Key::PPK.new(fixture_path('ecdsa-sha2-nistp384.ppk'))
      assert_raises(ArgumentError) { OpenSSL::PKey.from_ppk(ppk) }
    end

    def test_from_ppk_ecdsa_sha2_nistp384_encrypted
      ppk = PuTTY::Key::PPK.new(fixture_path('ecdsa-sha2-nistp384-encrypted.ppk'), 'Test Passphrase')
      assert_raises(ArgumentError) { OpenSSL::PKey.from_ppk(ppk) }
    end

    def test_from_ppk_ecdsa_sha2_nistp521
      ppk = PuTTY::Key::PPK.new(fixture_path('ecdsa-sha2-nistp521.ppk'))
      assert_raises(ArgumentError) { OpenSSL::PKey.from_ppk(ppk) }
    end

    def test_from_ppk_ecdsa_sha2_nistp521_encrypted
      ppk = PuTTY::Key::PPK.new(fixture_path('ecdsa-sha2-nistp521-encrypted.ppk'), 'Test Passphrase')
      assert_raises(ArgumentError) { OpenSSL::PKey.from_ppk(ppk) }
    end
  end

  def pem_to_ppk(fixture, type = nil)
    pem = load_fixture(fixture)

    # Accessing OpenSSL::PKey::EC#public_key raises a warning when the key was
    # loaded with OpenSSL::PKey.read(pem), but doesn't when instatiated with
    # OpenSSL::PKey::EC.new(pem) (Ruby 2.3.0).
    pkey = type ? type.new(pem) : OpenSSL::PKey.read(pem)

    pkey.to_ppk.tap do |ppk|
      assert_nil(ppk.comment)
    end
  end

  def test_to_ppk_rsa
    ppk = pem_to_ppk('rsa-2048.pem')
    ppk.comment = '2048 bit RSA key'
    temp_file_name do |file|
      ppk.save(file)
      assert_identical_to_fixture('rsa-2048.ppk', file)
    end
  end

  def test_to_ppk_rsa_encrypted
    ppk = pem_to_ppk('rsa-2048.pem')
    ppk.comment = '2048 bit RSA key'
    temp_file_name do |file|
      ppk.save(file, 'Test Passphrase')
      assert_identical_to_fixture('rsa-2048-encrypted.ppk', file)
    end
  end

  def test_to_ppk_rsa_uninitialized
    pkey = OpenSSL::PKey::RSA.new
    assert_raises(PuTTY::Key::InvalidStateError) { pkey.to_ppk }
  end

  def test_to_ppk_dss
    ppk = pem_to_ppk('dss-1024.pem')
    ppk.comment = '1024 bit DSS key'
    temp_file_name do |file|
      ppk.save(file)
      assert_identical_to_fixture('dss-1024.ppk', file)
    end
  end

  def test_to_ppk_dss_encrypted
    ppk = pem_to_ppk('dss-1024.pem')
    ppk.comment = '1024 bit DSS key'
    temp_file_name do |file|
      ppk.save(file, 'Test Passphrase')
      assert_identical_to_fixture('dss-1024-encrypted.ppk', file)
    end
  end

  def test_to_ppk_dss_uninitialized
    pkey = OpenSSL::PKey::DSA.new
    assert_raises(PuTTY::Key::InvalidStateError) { pkey.to_ppk }
  end

  # jruby-openssl doesn't include an EC class (version 0.9.15)
  if defined?(OpenSSL::PKey::EC)
    def test_to_ppk_ecdsa_sha2_nistp256
      ppk = pem_to_ppk('ecdsa-sha2-nistp256.pem', OpenSSL::PKey::EC)
      ppk.comment = 'ECDSA NIST P-256 Key'
      temp_file_name do |file|
        ppk.save(file)
        assert_identical_to_fixture('ecdsa-sha2-nistp256.ppk', file)
      end
    end

    def test_to_ppk_ecdsa_sha2_nistp256_encrypted
      ppk = pem_to_ppk('ecdsa-sha2-nistp256.pem', OpenSSL::PKey::EC)
      ppk.comment = 'ECDSA NIST P-256 Key'
      temp_file_name do |file|
        ppk.save(file, 'Test Passphrase')
        assert_identical_to_fixture('ecdsa-sha2-nistp256-encrypted.ppk', file)
      end
    end

    def test_to_ppk_ecdsa_sha2_nistp384
      ppk = pem_to_ppk('ecdsa-sha2-nistp384.pem', OpenSSL::PKey::EC)
      ppk.comment = 'ECDSA NIST P-384 Key'
      temp_file_name do |file|
        ppk.save(file)
        assert_identical_to_fixture('ecdsa-sha2-nistp384.ppk', file)
      end
    end

    def test_to_ppk_ecdsa_sha2_nistp384_encrypted
      ppk = pem_to_ppk('ecdsa-sha2-nistp384.pem', OpenSSL::PKey::EC)
      ppk.comment = 'ECDSA NIST P-384 Key'
      temp_file_name do |file|
        ppk.save(file, 'Test Passphrase')
        assert_identical_to_fixture('ecdsa-sha2-nistp384-encrypted.ppk', file)
      end
    end

    def test_to_ppk_ecdsa_sha2_nistp521
      ppk = pem_to_ppk('ecdsa-sha2-nistp521.pem', OpenSSL::PKey::EC)
      ppk.comment = 'ECDSA NIST P-521 Key'
      temp_file_name do |file|
        ppk.save(file)
        assert_identical_to_fixture('ecdsa-sha2-nistp521.ppk', file)
      end
    end

    def test_to_ppk_ecdsa_sha2_nistp521_encrypted
      ppk = pem_to_ppk('ecdsa-sha2-nistp521.pem', OpenSSL::PKey::EC)
      ppk.comment = 'ECDSA NIST P-521 Key'
      temp_file_name do |file|
        ppk.save(file, 'Test Passphrase')
        assert_identical_to_fixture('ecdsa-sha2-nistp521-encrypted.ppk', file)
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
      pkey = OpenSSL::PKey::EC.new
      assert_raises(PuTTY::Key::InvalidStateError) { pkey.to_ppk }
    end
  end
end
