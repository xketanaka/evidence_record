# frozen_string_literal: true

require_relative "test_helper"

class DERTest < Minitest::Test
  DER = EvidenceRecord::DER

  def parse(hex)
    DER.parse([hex.delete(" ")].pack("H*"), "test")
  end

  def assert_rejected(hex, pattern = nil)
    e = assert_raises(EvidenceRecord::ParseError) { parse(hex) }
    assert_match pattern, e.message if pattern
  end

  def test_nodes_keep_their_original_bytes
    node = parse("30 08 02 01 05 a0 03 04 01 ff")
    assert_equal [:universal, true, 16], [node.tag_class, node.constructed?, node.tag]
    int, tagged = node.children
    assert_equal ["020105"].pack("H*"), int.raw
    assert tagged.context?(0)
    assert_equal ["0401ff"].pack("H*"), tagged.children[0].raw
    assert_equal 5, DER.integer(int, "x")
  end

  def test_rejects_non_der_lengths
    assert_rejected("30 80 02 01 01 00 00", /indefinite/)
    assert_rejected("04 81 01 aa", /shortest/)
    assert_rejected("04 82 00 81" + ("aa" * 129), /shortest/)
    assert_rejected("04 05 aa", /truncated/)
    assert_rejected("04 01 aa bb", /trailing/)
  end

  def test_rejects_constructed_strings
    assert_rejected("24 06 04 01 61 04 01 62", /primitive/)
    assert_rejected("10 00", /constructed/)
  end

  def test_rejects_non_canonical_values
    assert_rejected("01 01 01")             # BOOLEAN true must be 0xff
    assert_rejected("02 02 00 7f")          # INTEGER with a redundant leading byte
    assert_rejected("02 02 ff 80")
    assert_rejected("02 00")
    assert_rejected("05 01 00")             # NULL with contents
    assert_rejected("03 02 07 81")          # unused bits not zero
    assert_rejected("06 02 2a 80")          # OID ending in the middle of a subidentifier
    assert_rejected("06 03 2a 80 01")       # non-minimal subidentifier
    assert_rejected("31 06 02 01 02 02 01 01") # SET elements not sorted
    assert_rejected("18 0f 32303234303130323033303430352e30") # trailing zero in a fraction
    assert_rejected("17 0b 3234303130323033303430")
    parse("01 01 ff")
    parse("02 02 00 80")
    parse("31 06 02 01 01 02 01 02")
  end

  def test_high_tag_numbers
    node = parse("9f 1f 00")
    assert_equal [:context, 31], [node.tag_class, node.tag]
    assert_rejected("9f 1e 00", /tag number/)
    assert_rejected("9f 80 1f 00", /tag number/)
  end

  def test_deep_nesting_is_rejected
    der = "".b
    100.times { der = DER.sequence([der]) }
    assert_raises(EvidenceRecord::ParseError) { DER.parse(der, "test") }
  end

  def test_oid
    assert_equal "1.2.840.113549.1.7.2", DER.oid(parse("06 09 2a864886f70d010702"), "x")
    assert_equal "2.999.3", DER.oid(DER.parse(DER.encode_oid("2.999.3"), "x"), "x")
    assert_equal "1.2.3.99999999", DER.oid(DER.parse(DER.encode_oid("1.2.3.99999999"), "x"), "x")
  end

  def test_negative_and_large_integers
    [-129, -1, 0, 127, 128, 2**64 + 5].each do |i|
      assert_equal i, DER.integer(DER.parse(DER.encode_integer(i), "x"), "x")
    end
  end

  def test_generalized_time_keeps_fractions
    t = DER.generalized_time(parse("18 13 #{'20240102030405.125Z'.unpack1('H*')}"), "x")
    assert_equal Time.utc(2024, 1, 2, 3, 4, Rational(5125, 1000)), t
    assert_equal 125_000, t.usec
    e = assert_raises(EvidenceRecord::ParseError) do
      DER.generalized_time(parse("18 0f #{'20240231030405Z'.unpack1('H*')}"), "x")
    end
    assert_match(/invalid time/, e.message)
  end

  def test_encode_length
    [0, 127, 128, 255, 256, 65_536].each do |n|
      der = DER.encode(0x04, "a" * n)
      assert_equal "a" * n, DER.parse(der, "x").content
    end
  end
end
