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
  gem 'coveralls', '~> 0.8', require: false if RUBY_VERSION < '2.3'
  gem 'coveralls_reborn', '~> 0.13', require: false if RUBY_VERSION >= '2.3'
end
