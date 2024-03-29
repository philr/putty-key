require_relative 'lib/putty/key/version'

Gem::Specification.new do |s|
  s.name = 'putty-key'
  s.version = PuTTY::Key::VERSION
  s.summary = 'PuTTY private key (.ppk) library. Supports reading and writing with a refinement to OpenSSL::PKey to allow key conversion.'
  s.description = <<-EOF
PuTTY::Key is a Ruby implementation of the PuTTY private key (ppk) format,
handling reading and writing .ppk files. It includes a refinement to Ruby's
OpenSSL library to add support for converting DSA, EC and RSA private keys to
and from PuTTY private key files. This allows OpenSSH ecdsa, ssh-dss and ssh-rsa
private keys to be converted to and from PuTTY's private key format.
  EOF
  s.author = 'Philip Ross'
  s.email = 'phil.ross@gmail.com'
  s.homepage = 'https://github.com/philr/putty-key'
  s.license = 'MIT'
  s.metadata = {
    'bug_tracker_uri' => 'https://github.com/philr/putty-key/issues',
    'changelog_uri' => 'https://github.com/philr/putty-key/blob/master/CHANGES.md',
    'documentation_uri' => "https://rubydoc.info/gems/#{s.name}/#{s.version}",
    'homepage_uri' => s.homepage,
    'source_code_uri' => "https://github.com/philr/putty-key/tree/v#{s.version}"
  }
  s.files = %w(CHANGES.md Gemfile LICENSE README.md Rakefile putty-key.gemspec .yardopts) +
            Dir['lib/**/*.rb'] +
            Dir['test/**/*.rb'] +
            Dir['test/fixtures/*']
  s.platform = Gem::Platform::RUBY
  s.require_path = 'lib'
  s.rdoc_options << '--title' << 'PuTTY::Key' <<
                    '--main' << 'README.md' <<
                    '--markup' << 'markdown'
  s.extra_rdoc_files = ['CHANGES.md', 'LICENSE', 'README.md']
  s.required_ruby_version = '>= 2.1.0'
  s.add_runtime_dependency 'ffi', '~> 1.0'
  s.requirements = ['libargon2 to handle format 3 .ppk files']
end
