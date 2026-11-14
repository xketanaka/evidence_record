# frozen_string_literal: true

require "bundler/gem_tasks"
require "rake/testtask"
require_relative "test/support/bsi_vectors"
require_relative "test/support/bouncy_castle"

Rake::TestTask.new(:test) do |t|
  t.libs << "test"
  t.test_files = FileList["test/**/*_test.rb"].exclude("test/interop/**/*")
end

# Interoperability tests with Bouncy Castle (needs a JDK and
# `rake test:fetch_bouncy_castle`).
Rake::TestTask.new("test:interop") do |t|
  t.libs << "test"
  t.test_files = FileList["test/interop/**/*_test.rb"]
end

task default: :test

# Downloads url into dest unless dest already has the given SHA-256.
def fetch_file(url, dest, sha256, label)
  require "digest"
  require "fileutils"
  require "net/http"

  if File.file?(dest) && Digest::SHA256.file(dest).hexdigest == sha256
    puts "ok       #{label}"
    return
  end

  uri = URI(url)
  res = Net::HTTP.get_response(uri)
  raise "failed to download #{uri}: #{res.code} #{res.message}" unless res.is_a?(Net::HTTPSuccess)

  body = res.body.b
  actual = Digest::SHA256.hexdigest(body)
  raise "SHA-256 mismatch for #{label}: expected #{sha256}, got #{actual}" unless actual == sha256

  FileUtils.mkdir_p(File.dirname(dest))
  File.binwrite(dest, body)
  puts "fetched  #{label}"
end

namespace :test do
  desc "Download the BSI Evidence Record test vectors into test/fixtures/bsi"
  task :fetch_vectors do
    BSIVectors::FILES.each do |relative, sha256|
      fetch_file(BSIVectors.url(relative), BSIVectors.path(relative), sha256, relative)
    end
  end

  desc "Download the Bouncy Castle jars for the interoperability tests into interop/lib"
  task :fetch_bouncy_castle do
    BouncyCastle::JARS.each do |artifact, sha256|
      fetch_file(BouncyCastle.url(artifact), BouncyCastle.path(artifact), sha256, BouncyCastle.file_name(artifact))
    end
  end
end
