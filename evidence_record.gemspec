# frozen_string_literal: true

require_relative "lib/evidence_record/version"

Gem::Specification.new do |spec|
  spec.name = "evidence_record"
  spec.version = EvidenceRecord::VERSION
  spec.authors = ["Ken Tanaka"]
  spec.email = ["tanaka-ken@netlab.jp"]

  spec.summary = "Evidence Record Syntax (ERS) compliant with RFC 4998"
  spec.description = "Generation, timestamp renewal, hash-tree renewal and verification of " \
                     "Evidence Records as defined in RFC 4998, with no runtime dependencies " \
                     "beyond the Ruby standard library."
  spec.homepage = "https://github.com/xketanaka/evidence_record"
  spec.license = "MIT"
  spec.required_ruby_version = ">= 3.3"

  spec.files = Dir["lib/**/*.rb", "LICENSE.txt", "README.md"]
  spec.require_paths = ["lib"]
  spec.metadata["source_code_uri"] = spec.homepage
  spec.metadata["bug_tracker_uri"] = "#{spec.homepage}/issues"
  spec.metadata["documentation_uri"] = "#{spec.homepage}/blob/main/README.md"
  spec.metadata["rubygems_mfa_required"] = "true"
end
