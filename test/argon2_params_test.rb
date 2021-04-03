# frozen_string_literal: true

require_relative 'test_helper'

class Argon2ParamsTest < Minitest::Test
  [:d, :i, :id].each do |type|
    define_method("test_valid_type_#{type}") do
      params = PuTTY::Key::Argon2Params.new(type: type)
      assert_equal(type, params.type)
    end
  end

  [nil, :x, 'd'].each do |type|
    define_method("test_invalid_type_#{type.class.name.downcase}_#{type || 'nil'}") do
      assert_raises(ArgumentError) { PuTTY::Key::Argon2Params.new(type: type) }
    end
  end

  [0, 1024, 16384].each do |memory|
    define_method("test_valid_memory_#{memory}") do
      params = PuTTY::Key::Argon2Params.new(memory: memory)
      assert_equal(memory, params.memory)
    end
  end

  [-1, 1024.1, '1024', nil].each do |memory|
    define_method("test_invalid_memory_#{memory.class.name.downcase}_#{memory}") do
      assert_raises(ArgumentError) { PuTTY::Key::Argon2Params.new(memory: memory) }
    end
  end

  [nil, 0, 10].each do |passes|
    define_method("test_valid_passes_#{passes || 'nil'}") do
      params = PuTTY::Key::Argon2Params.new(passes: passes)
      if passes
        assert_equal(passes, params.passes)
      else
        assert_nil(params.passes)
      end
    end
  end

  [-1, 1.1, '1'].each do |passes|
    define_method("test_invalid_passes_#{passes.class.name.downcase}_#{passes}") do
      assert_raises(ArgumentError) { PuTTY::Key::Argon2Params.new(passes: passes) }
    end
  end

  [0, 2].each do |parallelism|
    define_method("test_valid_parallelism_#{parallelism}") do
      params = PuTTY::Key::Argon2Params.new(parallelism: parallelism)
      assert_equal(parallelism, params.parallelism)
    end
  end

  [nil, -1, 2.1, '2'].each do |parallelism|
    define_method("test_invalid_parallelism_#{parallelism.class.name.downcase}_#{parallelism || 'nil'}") do
      assert_raises(ArgumentError) { PuTTY::Key::Argon2Params.new(parallelism: parallelism) }
    end
  end

  [nil, '', "\x00".b, 'salt'].each do |salt|
    define_method("test_valid_salt_#{salt || 'nil'}") do
      params = PuTTY::Key::Argon2Params.new(salt: salt)
      if salt
        assert_equal(salt, params.salt)
      else
        assert_nil(params.salt)
      end
    end
  end

  [0, :salt].each do |salt|
    define_method("test_invalid_salt_#{salt.class.name.downcase}_#{salt}") do
      assert_raises(ArgumentError) { PuTTY::Key::Argon2Params.new(salt: salt) }
    end
  end

  [0, 200, 200.1, Rational(2001, 1)].each do |desired_time|
    define_method("test_valid_desired_time_#{desired_time.class.name.downcase}_#{desired_time}") do
      params = PuTTY::Key::Argon2Params.new(desired_time: desired_time)
      assert_equal(desired_time, params.desired_time)
    end
  end

  [nil, -1, -0.1, Rational(-1, 10), '0'].each do |desired_time|
    define_method("test_invalid_desired_time_#{desired_time.class.name.downcase}_#{desired_time || 'nil'}") do
      assert_raises(ArgumentError) { PuTTY::Key::Argon2Params.new(desired_time: desired_time) }
    end
  end

  def test_complete_with_equivalent_passes_and_salt
    params = PuTTY::Key::Argon2Params.new(passes: 10, salt: 'test_salt')
    assert_same(params, params.complete(10, 'test_salt'.dup))
  end

  def test_complete_with_equivalent_passes_and_different_salt
    params = PuTTY::Key::Argon2Params.new(passes: 10, salt: nil)
    complete_params = params.complete(10, 'test_salt')
    refute_same(params, complete_params)
    assert_equal(10, complete_params.passes)
    assert_equal('test_salt', complete_params.salt)
  end

  def test_complete_with_different_passes_and_equivalent_salt
    params = PuTTY::Key::Argon2Params.new(passes: nil, salt: 'test_salt')
    complete_params = params.complete(10, 'test_salt'.dup)
    refute_same(params, complete_params)
    assert_equal(10, complete_params.passes)
    assert_equal('test_salt', complete_params.salt)
  end

  def test_complete_with_different_passes_and_salt
    params = PuTTY::Key::Argon2Params.new(passes: nil, salt: nil)
    complete_params = params.complete(10, 'test_salt')
    refute_same(params, complete_params)
    assert_equal(10, complete_params.passes)
    assert_equal('test_salt', complete_params.salt)
  end

  def test_complete_copies_other_properties
    params = PuTTY::Key::Argon2Params.new(type: :d, memory: 8193, parallelism: 3, passes: nil, salt: nil, desired_time: 123)
    complete_params = params.complete(10, 'test_salt')
    refute_same(params, complete_params)
    assert_equal(:d, complete_params.type)
    assert_equal(8193, complete_params.memory)
    assert_equal(3, complete_params.parallelism)
    assert_equal(123, complete_params.desired_time)
  end

  [nil, -1, 1.1, '1'].each do |passes|
    define_method("test_complete_with_invalid_passes_#{passes.class.name.downcase}_#{passes || 'nil'}") do
      params = PuTTY::Key::Argon2Params.new(passes: nil, salt: nil)
      assert_raises(ArgumentError) { params.complete(passes, 'test_salt') }
    end
  end

  [nil, 0, :test_salt].each do |salt|
    define_method("test_complete_with_invalid_salt_#{salt.class.name.downcase}_#{salt || 'nil'}") do
      params = PuTTY::Key::Argon2Params.new(passes: nil, salt: nil)
      assert_raises(ArgumentError) { params.complete(10, salt) }
    end
  end
end
