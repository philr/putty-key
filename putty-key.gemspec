require File.expand_path(File.join('..', 'lib', 'putty', 'key', 'version'), __FILE__)

Gem::Specification.new do |s|
  s.name = 'putty-key'
  s.version = PuTTY::Key::VERSION
  s.summary = 'Reads and writes PuTTY private key (.ppk) files. Refines OpenSSL::PKey to allow key conversion.'
  s.description = <<-EOF
PuTTY::Key is a pure-Ruby implementation of the PuTTY private key (ppk) format,
handling reading and writing .ppk files. It includes a refinement to Ruby's
OpenSSL library to add support for converting DSA, EC and RSA private keys to
and from PuTTY private key files. This allows OpenSSH ecdsa, ssh-dss and ssh-rsa
private keys to be converted to and from PuTTY's private key format.
  EOF
  s.author = 'Philip Ross'
  s.email = 'phil.ross@gmail.com'
  s.homepage = 'https://github.com/philr/putty-key'
  s.license = 'MIT'
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
end
