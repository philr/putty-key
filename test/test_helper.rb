TEST_TYPE = (ENV['TEST_TYPE'] || 'refinement').to_sym
raise "Unrecognized TEST_TYPE: #{TEST_TYPE}" unless [:refinement, :global].include?(TEST_TYPE)

# Don't run coverage tests on JRuby due to inaccurate results.
# Don't run coverage tests on platforms that don't support refinements, since
# it won't be possible to get complete coverage.
if RUBY_ENGINE != 'jruby' && respond_to?(:using, true)
  require 'simplecov'
  require 'coveralls'

  SimpleCov.command_name TEST_TYPE.to_s

  SimpleCov.formatters = [
    SimpleCov::Formatter::HTMLFormatter
  ]

  SimpleCov.start do
    add_filter 'test'
    project_name 'PuTTY::Key'
  end
end

require 'putty/key'

require 'fileutils'
require 'minitest/autorun'
require 'tmpdir'

PuTTY::Key.global_install if TEST_TYPE == :global

module TestHelper
  BASE_DIR = File.expand_path(File.dirname(__FILE__))

  module Assertions
    def assert_files_identical(exp, act, msg = nil)
      msg = message(msg) { "Expected file #{act} to be identical to #{exp}\n\n#{act}:\n#{File.read(act)}\n\n#{exp}:\n#{File.read(exp)}\n" }
      assert(FileUtils.identical?(exp, act), msg)
    end

    def assert_identical_to_fixture(exp_fixture, act_file, msg = nil)
      assert_files_identical(fixture_path(exp_fixture), act_file, msg)
    end
  end

  module Fixtures
    FIXTURES_DIR = File.join(BASE_DIR, 'fixtures')

    def fixture_path(fixture)
      File.join(FIXTURES_DIR, fixture)
    end

    def load_fixture(fixture)
      File.read(fixture_path(fixture), mode: 'rb')
    end
  end

  module Utils
    def temp_dir(&block)
      Dir.mktmpdir('putty-key', &block)
    end

    def temp_file_name(name = nil)
      temp_dir do |dir|
        file = File.join(dir, name || 'test')
        yield file
      end
    end
  end

  class ::OpenSSL::BN
    # Override to_s so the represented value is visible.
    def inspect
      "#<OpenSSL::BN:#{to_s(16)}>"
    end
  end
end

class Minitest::Test
  include TestHelper::Assertions
  include TestHelper::Fixtures
  include TestHelper::Utils
end
