# encoding: UTF-8

require 'test_helper'
require 'openssl'

class PPKTest < Minitest::Test
  def test_ssh_pack_empty
    s = PuTTY::Key::Util.ssh_pack
    assert_equal(Encoding::ASCII_8BIT, s.encoding)
    assert_equal("".b, s)
  end

  def test_ssh_pack_nil_element
    assert_raises(ArgumentError) { PuTTY::Key::Util.ssh_pack('test', nil, 'test2') }
  end

  def ssh_pack_string_empty
    s = PuTTY::Key::Util.ssh_pack('')
    assert_equal(Encoding::ASCII_8BIT, s.encoding)
    assert_equal("\x00\x00\x00\x00".b, s)
  end

  def test_ssh_pack_string_utf8
    s = PuTTY::Key::Util.ssh_pack('This is UTF-8: ✓')
    assert_equal(Encoding::ASCII_8BIT, s.encoding)
    assert_equal("\x00\x00\x00\x12This is UTF-8: \xe2\x9c\x93".b, s)
  end

  def test_ssh_pack_string_binary
    s = PuTTY::Key::Util.ssh_pack("\x00\x01\x02\x03\x04".b)
    assert_equal(Encoding::ASCII_8BIT, s.encoding)
    assert_equal("\x00\x00\x00\x05\x00\x01\x02\x03\x04".b, s)
  end

  def test_ssh_pack_bn
    s = PuTTY::Key::Util.ssh_pack(OpenSSL::BN.new(12345678901234567890))
    assert_equal(Encoding::ASCII_8BIT, s.encoding)
    assert_equal("\x00\x00\x00\x09\x00\xab\x54\xa9\x8c\xeb\x1f\x0a\xd2".b, s)
  end

  def test_ssh_pack_mixed
    s = PuTTY::Key::Util.ssh_pack('string1', OpenSSL::BN.new(42), 'string2', OpenSSL::BN.new(1764))
    assert_equal(Encoding::ASCII_8BIT, s.encoding)
    assert_equal("\x00\x00\x00\x07string1\x00\x00\x00\x01\x2a\x00\x00\x00\x07string2\x00\x00\x00\x02\x06\xe4".b, s)
  end

  def test_ssh_unpack_encoded_nil
    assert_raises(ArgumentError) { PuTTY::Key::Util.ssh_unpack(nil) }
  end

  def test_ssh_unpack_encoded_not_binary
    assert_raises(ArgumentError) { PuTTY::Key::Util.ssh_unpack('\x00\x00\x00\x12This is UTF-8: ✓', :string) }
  end

  def test_ssh_unpack_spec_empty
    assert_equal([], PuTTY::Key::Util.ssh_unpack("\x00\x00\x00\x06string".b))
  end

  def test_ssh_unpack_spec_invalid
    assert_raises(ArgumentError) { PuTTY::Key::Util.ssh_unpack("\x00\x00\x00\x07string1\x00\x00\x00\x07string2\x00\x00\x00\x07string3".b, :string, :unknown, :string) }
  end

  def test_ssh_unpack_spec_longer_than_encoded
    assert_raises(PuTTY::Key::FormatError) { PuTTY::Key::Util.ssh_unpack("\x00\x00\x00\x06string".b, :string, :string) }
  end

  def test_ssh_unpack_encoded_truncated_value
    assert_raises(PuTTY::Key::FormatError) { PuTTY::Key::Util.ssh_unpack("\x00\x00\x00\x06str".b, :string) }
  end

  def test_ssh_unpack_encoded_truncated_length
    assert_raises(PuTTY::Key::FormatError) { PuTTY::Key::Util.ssh_unpack("\x00\x00".b, :string) }
  end

  def test_ssh_unpack_encoded_missing_value
    assert_raises(PuTTY::Key::FormatError) { PuTTY::Key::Util.ssh_unpack("\x00\x00\x00\x06".b, :string) }
  end

  def test_ssh_unpack_string_empty
    a = PuTTY::Key::Util.ssh_unpack("\x00\x00\x00\x00".b, :string)
    assert_equal([''.b], a)
    assert_kind_of(String, a[0])
    assert_equal(Encoding::ASCII_8BIT, a[0].encoding)
  end

  def test_ssh_unpack_string_utf8
    a = PuTTY::Key::Util.ssh_unpack("\x00\x00\x00\x12This is UTF-8: \xe2\x9c\x93".b, :string)
    assert_equal(["This is UTF-8: \xe2\x9c\x93".b], a)
    assert_kind_of(String, a[0])
    assert_equal(Encoding::ASCII_8BIT, a[0].encoding)
  end

  def test_ssh_unpack_string_binary
    a = PuTTY::Key::Util.ssh_unpack("\x00\x00\x00\x05\x00\x01\x02\x03\x04".b, :string)
    assert_equal(["\x00\x01\x02\x03\x04".b], a)
    assert_kind_of(String, a[0])
    assert_equal(Encoding::ASCII_8BIT, a[0].encoding)
  end

  def test_ssh_unpack_bn
    a = PuTTY::Key::Util.ssh_unpack("\x00\x00\x00\x09\x00\xab\x54\xa9\x8c\xeb\x1f\x0a\xd2".b, :mpint)
    assert_equal([OpenSSL::BN.new(12345678901234567890)], a)
    assert_kind_of(OpenSSL::BN, a[0])
  end

  def test_ssh_unpack_mixed
    a = PuTTY::Key::Util.ssh_unpack("\x00\x00\x00\x07string1\x00\x00\x00\x01\x2a\x00\x00\x00\x07string2\x00\x00\x00\x02\x06\xe4".b, :string, :mpint, :string, :mpint)
    assert_equal(['string1', OpenSSL::BN.new(42), 'string2', OpenSSL::BN.new(1764)], a)
    assert_kind_of(String, a[0])
    assert_kind_of(OpenSSL::BN, a[1])
    assert_kind_of(String, a[2])
    assert_kind_of(OpenSSL::BN, a[3])
    assert_equal(Encoding::ASCII_8BIT, a[0].encoding)
    assert_equal(Encoding::ASCII_8BIT, a[2].encoding)
  end
end
