require File.expand_path(File.join('..', 'lib', 'putty', 'key', 'version'), __FILE__)

Gem::Specification.new do |s|
  s.name = 'putty-key'
  s.version = PuTTY::Key::VERSION
  s.summary = 'Refines OpenSSL::PKey to support converting to and from PuTTY private key (PPK) format.'
  s.description = <<-EOF
PuTTY::Key contains a refinement to OpenSSL::PKey to add support for converting
OpenSSL::PKey::DSA and OpenSSL::PKey::RSA private keys to and from the PuTTY
private key (PPK) format. This allows DSA and RSA OpenSSH keys to be converted
for use with PuTTY and vice-versa.
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
