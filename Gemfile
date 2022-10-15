source "https://rubygems.org"

gemspec

group :development do
  gem 'rake', ['>= 12.3.3', '< 14']
  gem 'git', '~> 1.2', require: false
end

group :test do
  gem 'minitest', '~> 5.8'

  # coveralls is no longer maintained, but supports Ruby < 2.3.
  # coveralls_reborn is maintained, but requires Ruby >= 2.3.
  gem 'coveralls', git: 'https://github.com/philr/coveralls-ruby.git', require: false if RUBY_VERSION < '2.3'
  gem 'coveralls_reborn', '~> 0.13', require: false if RUBY_VERSION >= '2.3'

  # The source version of ffi 1.15.5 is declared as compatible with Ruby >= 2.3.
  # The binary version of 1.15.5 is declared as compatible with Ruby >= 2.4, so
  # doesn't get used. The using the source version results in a segmentation
  # fault during libffi initialization.
  #
  # Binaries of 15.5.0 to 15.5.4 are declared as compatible with Ruby >= 2.3,
  # but don't get used with Bundler 2.3.23 and Ruby 2.3 on Windows.
  #
  # Limit to earlier compatible versions.
  gem 'ffi', '< 1.15.0' if RUBY_VERSION < '2.4' && RUBY_PLATFORM =~ /mingw/
end
