require 'fileutils'
require 'rubygems'
require 'rubygems/package_task'
require 'rake/testtask'

BASE_DIR = File.expand_path(File.dirname(__FILE__))
GEMSPEC_PATH = File.join(BASE_DIR, 'putty-key.gemspec')
spec = TOPLEVEL_BINDING.eval(File.read(GEMSPEC_PATH), GEMSPEC_PATH)

task :default => :test

# Attempt to find the private key and return a spec with added options for
# signing the gem if found.
def add_signing_key(spec)
  private_key_path = File.expand_path(File.join(BASE_DIR, '..', 'key', 'gem-private_key.pem'))

  if File.exist?(private_key_path)
    spec = spec.clone
    spec.signing_key = private_key_path
    spec.cert_chain = [File.join(BASE_DIR, 'gem-public_cert.pem')]
  else
    puts 'WARNING: Private key not found. Not signing gem file.'
  end

  spec
end

package_task = Gem::PackageTask.new(add_signing_key(spec)) do
end

# Ensure files are world-readable before packaging.
Rake::Task[package_task.package_dir_path].enhance do
  recurse_chmod(package_task.package_dir_path)
end

def recurse_chmod(dir)
  File.chmod(0755, dir)

  Dir.entries(dir).each do |entry|
    if entry != '.' && entry != '..'
      path = File.join(dir, entry)
      if File.directory?(path)
        recurse_chmod(path)
      else
        File.chmod(0644, path)
      end
    end
  end
end

desc 'Create a tag for the current version'
task :tag do
  require 'git'
  g = Git.init(BASE_DIR)
  g.add_tag("v#{spec.version}", annotate: true, message: "Tagging v#{spec.version}")
end

def define_test_task(type, test_coverage)
  type = type.to_s

  env_task = "test:env:#{type}"
  Rake::Task::define_task(env_task) do
    ENV['TEST_COVERAGE'] = test_coverage ? '1' : '0'
    ENV['TEST_TYPE'] = type
  end

  test_task = "test:#{type}"
  Rake::TestTask.new(test_task) do |t|
    t.libs = [File.join(BASE_DIR, 'test')]
    t.pattern = File.join(BASE_DIR, 'test', '**', '*_test.rb')
    t.warning = true
  end

  Rake::Task[test_task].enhance([env_task])
end

if RUBY_ENGINE == 'jruby'
  # Don't run coverage tests on JRuby due to inaccurate results.
  TEST_COVERAGE = false

  define_test_task(:refinement, TEST_COVERAGE)
elsif !respond_to?(:using, true)
  # Don't run coverage tests on platforms that don't support refinements, since
  # it won't be possible to get complete coverage.
  TEST_COVERAGE = false

  task 'test:refinement' do
    puts "Skipping refinement tests because #{RUBY_DESCRIPTION} lacks support for refinements"
  end
else
  TEST_COVERAGE = true
  define_test_task(:refinement, TEST_COVERAGE)
end

define_test_task(:global, TEST_COVERAGE)

require 'coveralls/rake/task'
Coveralls::RakeTask.new

desc 'Remove coverage results'
task :clean_coverage do
  FileUtils.rm_f(File.join(BASE_DIR, 'coverage', '.resultset.json'))
end

desc 'Run tests using the refinement, then with the global install'
task :test => [:clean_coverage, 'test:refinement', 'test:global'] + (TEST_COVERAGE ? ['coveralls:push'] : []) do
end

# Coveralls expects an sh compatible shell when running git commands with Kernel#`
# On Windows, the results end up wrapped in single quotes.
# Patch Coveralls::Configuration to remove the quotes.
if RUBY_PLATFORM =~ /mingw/
  module CoverallsFixConfigurationOnWindows
    def self.included(base)
      base.instance_eval do
        class << self
          alias_method :git_without_windows_fix, :git

          def git
            git_without_windows_fix.tap do |hash|
              hash[:head] = hash[:head].map {|k, v| [k, v =~ /\A'(.*)'\z/ ? $1 : v] }.to_h
            end
          end
        end
      end
    end
  end

  require 'coveralls'
  Coveralls::Configuration.send(:include, CoverallsFixConfigurationOnWindows)
end
