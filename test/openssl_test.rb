require 'test_helper'

using PuTTY::Key if TEST_TYPE == :refinement

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

  def pem_to_ppk(fixture)
    pkey = OpenSSL::PKey.read(load_fixture(fixture))
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
end
