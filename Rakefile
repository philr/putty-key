require 'fileutils'
require 'rubygems'
require 'rubygems/package_task'
require 'rake/testtask'

BASE_DIR = File.expand_path(File.dirname(__FILE__))

task :default => :test

spec ||= eval(File.read('putty-key.gemspec'))

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

task :tag do
  require 'git'
  g = Git.init(BASE_DIR)
  g.add_tag("v#{spec.version}", annotate: true, message: "Tagging v#{spec.version}")
end

def define_test_task(type)
  type = type.to_s

  env_task = "test:env:#{type}"
  Rake::Task::define_task(env_task) do
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

# JRuby 9.0.5.0 doesn't handle refinements correctly.
if RUBY_PLATFORM == 'java'
  task 'test:refinement' do
    puts 'Skipping refinement tests on JRuby'
  end
else
  define_test_task(:refinement)
end

define_test_task(:global)

require 'coveralls/rake/task'
Coveralls::RakeTask.new

task :clean_coverage do
  FileUtils.rm_f(File.join(BASE_DIR, 'coverage', '.resultset.json'))
end

desc 'Run tests using the refinement, then with the global install'
task :test => [:clean_coverage, 'test:refinement', 'test:global', 'coveralls:push'] do
end
