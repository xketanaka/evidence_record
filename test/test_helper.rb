# frozen_string_literal: true

$LOAD_PATH.unshift File.expand_path("../lib", __dir__)
require "evidence_record"
require "minitest/autorun"
require_relative "support/bsi_vectors"

module VectorHelper
  # Skips the current test unless `rake test:fetch_vectors` has been run.
  def require_bsi_vectors!
    skip "BSI test vectors not found; run `rake test:fetch_vectors`" unless BSIVectors.available?
  end
end
