# frozen_string_literal: true

require_relative "test_helper"
require "pathname"
require "stringio"

class DataTest < Minitest::Test
  DS = EvidenceRecord::DataSource
  DA = EvidenceRecord::DigestAlgorithm

  def sha(alg, data)
    OpenSSL::Digest.digest(alg, data)
  end

  def test_string_is_hashed_as_bytes_regardless_of_encoding
    utf8 = "データ"
    assert_equal sha("SHA256", utf8.b), DS.wrap(utf8).digest(:sha256)
    assert_equal DS.wrap(utf8).digest(:sha256), DS.wrap(utf8.b).digest(:sha256)
  end

  def test_every_supported_algorithm
    DA::ALL.each do |a|
      assert_equal sha(a.name.to_s.upcase, "abc"), DS.wrap("abc").digest(a)
    end
  end

  def test_string_is_not_treated_as_a_path
    assert_equal sha("SHA256", __FILE__), DS.wrap(__FILE__).digest(:sha256)
  end

  def test_digests_are_cached_per_algorithm
    src = DS.wrap("abc")
    assert_same src.digest(:sha256), src.digest(:sha256)
    refute_equal src.digest(:sha256), src.digest(:sha512)
  end

  def test_prehashed_data
    d256 = sha("SHA256", "abc")
    pre = EvidenceRecord::PrehashedData.new(sha256: d256, sha512: EvidenceRecord::Digest.new(sha("SHA512", "abc")))
    assert_equal [DA::SHA256, DA::SHA512], pre.algorithms
    assert_equal EvidenceRecord::Digest.new(d256), pre[:sha256]
    assert_nil pre[:sha384]
    assert_equal d256, DS.wrap(pre).digest(:sha256)
    assert_raises(ArgumentError) { DS.wrap(pre).digest(:sha384) }
  end

  def test_prehashed_data_validation
    assert_raises(ArgumentError) { EvidenceRecord::PrehashedData.new }
    assert_raises(ArgumentError) { EvidenceRecord::PrehashedData.new(sha256: "short") }
    assert_raises(ArgumentError) { EvidenceRecord::PrehashedData.new(sha256: 1) }
    assert_raises(EvidenceRecord::UnsupportedAlgorithmError) do
      EvidenceRecord::PrehashedData.new(sha1: "x" * 20)
    end
  end

  def test_data_group
    group = EvidenceRecord::DataGroup.new(["a", "b", EvidenceRecord::PrehashedData.new(sha256: sha("SHA256", "c"))])
    assert_equal 3, group.size
    assert group.frozen?
    src = DS.wrap(group)
    assert src.group?
    assert_equal %w[a b c].map { sha("SHA256", _1) }, src.member_digests(:sha256)
  end

  def test_data_group_validation
    assert_raises(ArgumentError) { EvidenceRecord::DataGroup.new([]) }
    assert_raises(ArgumentError) { EvidenceRecord::DataGroup.new("a") }
    assert_raises(ArgumentError) { EvidenceRecord::DataGroup.new([EvidenceRecord::DataGroup.new(["a"])]) }
    assert_raises(ArgumentError) { EvidenceRecord::DataGroup.new([StringIO.new("a")]) }
  end

  def test_unsupported_data
    assert_raises(ArgumentError) { DS.wrap(123) }
    assert_raises(ArgumentError) { DS.wrap(StringIO.new("abc")) }
    assert_raises(ArgumentError) { DS.wrap(Pathname(__FILE__)) }
    assert_raises(ArgumentError) { DS.wrap(EvidenceRecord::Digest.new("x" * 32)) }
  end
end
