# frozen_string_literal: true

require_relative "test_helper"

class EvidenceRecordTest < Minitest::Test
  include VectorHelper

  def test_version
    assert_match(/\A\d+\.\d+\.\d+/, EvidenceRecord::VERSION)
  end

  def test_error_hierarchy
    assert_operator EvidenceRecord::Error, :<, StandardError
    [EvidenceRecord::ParseError, EvidenceRecord::UnsupportedAlgorithmError,
     EvidenceRecord::TimestampResponseError, EvidenceRecord::VerificationError].each do |klass|
      assert_operator klass, :<, EvidenceRecord::Error
    end
    [EvidenceRecord::MalformedRecordError, EvidenceRecord::HashMismatchError,
     EvidenceRecord::TimestampInvalidError].each do |klass|
      assert_operator klass, :<, EvidenceRecord::VerificationError
    end
  end

  def test_verification_error_location
    e = EvidenceRecord::HashMismatchError.new("root mismatch", chain_index: 1, ats_index: 0)
    assert_equal "root mismatch", e.message
    assert_equal 1, e.chain_index
    assert_equal 0, e.ats_index
    assert_nil EvidenceRecord::MalformedRecordError.new("empty").chain_index
  end

  def test_bsi_vectors_are_intact
    require_bsi_vectors!
    require "digest"
    BSIVectors::FILES.each do |relative, sha256|
      assert_equal sha256, Digest::SHA256.file(BSIVectors.path(relative)).hexdigest, relative
    end
  end
end
