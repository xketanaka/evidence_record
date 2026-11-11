# frozen_string_literal: true

require_relative "test_helper"

class DigestTest < Minitest::Test
  HEX = "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"

  def test_conversions
    d = EvidenceRecord::Digest.from_hex(HEX)
    assert_equal HEX, d.to_hex
    assert_equal HEX, d.to_s
    assert_equal 32, d.bytesize
    assert_equal Encoding::BINARY, d.to_binary.encoding
    assert d.to_binary.frozen?
    assert d.frozen?
    assert_equal d, EvidenceRecord::Digest.from_base64(d.to_base64)
    assert_equal "#<EvidenceRecord::Digest #{HEX}>", d.inspect
  end

  def test_uppercase_hex_is_accepted
    assert_equal HEX, EvidenceRecord::Digest.from_hex(HEX.upcase).to_hex
  end

  def test_invalid_input
    assert_raises(ArgumentError) { EvidenceRecord::Digest.from_hex("abc") }
    assert_raises(ArgumentError) { EvidenceRecord::Digest.from_hex("zz") }
    assert_raises(ArgumentError) { EvidenceRecord::Digest.from_hex(nil) }
    assert_raises(ArgumentError) { EvidenceRecord::Digest.from_base64("!!") }
    assert_raises(ArgumentError) { EvidenceRecord::Digest.new(123) }
  end

  def test_equality
    a = EvidenceRecord::Digest.from_hex(HEX)
    b = EvidenceRecord::Digest.new(a.to_binary.dup)
    assert_equal a, b
    assert a.eql?(b)
    assert_equal a.hash, b.hash
    assert_equal a, a.to_binary.dup.force_encoding(Encoding::UTF_8)
    refute a.eql?(a.to_binary)
    refute_equal a, 1
  end

  def test_wrap_and_bytes_of
    d = EvidenceRecord::Digest.from_hex(HEX)
    assert_same d, EvidenceRecord::Digest.wrap(d)
    assert_equal d, EvidenceRecord::Digest.wrap(d.to_binary)
    assert_equal d.to_binary, EvidenceRecord::Digest.bytes_of(d)
    assert_raises(ArgumentError) { EvidenceRecord::Digest.bytes_of(:x) }
  end
end
