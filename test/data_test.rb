# frozen_string_literal: true

require_relative "test_helper"
require "stringio"
require "tempfile"

class DataTest < Minitest::Test
  DS = EvidenceRecord::DataSource
  DA = EvidenceRecord::DigestAlgorithm

  def sha(alg, data)
    OpenSSL::Digest.digest(alg, data)
  end

  def test_string_is_hashed_as_bytes_regardless_of_encoding
    utf8 = "データ"
    binary = utf8.b
    assert_equal sha("SHA256", binary), DS.wrap(utf8).digest(:sha256)
    assert_equal DS.wrap(utf8).digest(:sha256), DS.wrap(binary).digest(:sha256)
  end

  def test_string_is_not_treated_as_a_path
    Tempfile.create("er") do |f|
      f.write("content")
      f.flush
      assert_equal sha("SHA256", f.path), DS.wrap(f.path).digest(:sha256)
      assert_equal sha("SHA256", "content"), DS.wrap(Pathname(f.path)).digest(:sha256)
    end
  end

  def test_io_and_pathname_match_string
    data = Random.new(1).bytes(200_000) # larger than one chunk
    Tempfile.create("er", binmode: true) do |f|
      f.write(data)
      f.flush
      DA::ALL.each do |a|
        expected = sha(a.name.to_s.upcase, data)
        assert_equal expected, DS.wrap(data).digest(a)
        assert_equal expected, DS.wrap(Pathname(f.path)).digest(a)
        assert_equal expected, DS.wrap(StringIO.new(data)).digest(a)
      end
    end
  end

  def test_io_is_read_once_for_prefetched_algorithms
    io = StringIO.new("abc")
    src = DS.wrap(io)
    src.prefetch(%i[sha256 sha512])
    assert io.eof?
    assert_equal sha("SHA256", "abc"), src.digest(:sha256)
    assert_equal sha("SHA512", "abc"), src.digest(:sha512)
  end

  def test_seekable_io_is_rewound_to_its_start_for_another_algorithm
    io = StringIO.new("skip-abc")
    io.read(5)
    src = DS.wrap(io)
    assert_equal sha("SHA256", "abc"), src.digest(:sha256)
    assert_equal sha("SHA384", "abc"), src.digest(:sha384)
  end

  def test_non_seekable_io_cannot_be_read_twice
    reader = Class.new do
      def initialize(data) = @io = StringIO.new(data)
      def read(n) = @io.read(n)
    end
    src = DS.wrap(reader.new("abc"))
    assert_equal sha("SHA256", "abc"), src.digest(:sha256)
    assert_equal sha("SHA256", "abc"), src.digest(:sha256) # cached
    assert_raises(ArgumentError) { src.digest(:sha512) }
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
    group = EvidenceRecord::DataGroup.new(["a", StringIO.new("b"), EvidenceRecord::PrehashedData.new(sha256: sha("SHA256", "c"))])
    assert_equal 3, group.size
    src = DS.wrap(group)
    assert src.group?
    assert_equal %w[a b c].map { sha("SHA256", _1) }, src.member_digests(:sha256)
  end

  def test_data_group_validation
    assert_raises(ArgumentError) { EvidenceRecord::DataGroup.new([]) }
    assert_raises(ArgumentError) { EvidenceRecord::DataGroup.new("a") }
    assert_raises(ArgumentError) { EvidenceRecord::DataGroup.new([EvidenceRecord::DataGroup.new(["a"])]) }
    assert_raises(ArgumentError) { EvidenceRecord::DataGroup.new([1]) }
  end

  def test_unsupported_data
    assert_raises(ArgumentError) { DS.wrap(123) }
    assert_raises(ArgumentError) { DS.wrap(EvidenceRecord::Digest.new("x" * 32)) }
  end
end
