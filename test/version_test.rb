require 'test_helper'

class VersionTest < Minitest::Test
  def test_version
    assert(PuTTY::Key::VERSION =~ /\A\d+(\.\d+){2}\z/)
  end
end
