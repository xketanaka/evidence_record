# frozen_string_literal: true

require "bundler/gem_tasks"
require "rake/testtask"
require_relative "test/support/bsi_vectors"

Rake::TestTask.new(:test) do |t|
  t.libs << "test"
  t.test_files = FileList["test/**/*_test.rb"]
end

task default: :test

namespace :test do
  desc "Download the BSI Evidence Record test vectors into test/fixtures/bsi"
  task :fetch_vectors do
    require "digest"
    require "fileutils"
    require "net/http"

    BSIVectors::FILES.each do |relative, sha256|
      dest = BSIVectors.path(relative)
      if File.file?(dest) && Digest::SHA256.file(dest).hexdigest == sha256
        puts "ok       #{relative}"
        next
      end

      uri = URI(BSIVectors.url(relative))
      res = Net::HTTP.get_response(uri)
      raise "failed to download #{uri}: #{res.code} #{res.message}" unless res.is_a?(Net::HTTPSuccess)

      body = res.body.b
      actual = Digest::SHA256.hexdigest(body)
      raise "SHA-256 mismatch for #{relative}: expected #{sha256}, got #{actual}" unless actual == sha256

      FileUtils.mkdir_p(File.dirname(dest))
      File.binwrite(dest, body)
      puts "fetched  #{relative}"
    end
  end
end
