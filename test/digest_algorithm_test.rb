# frozen_string_literal: true

require_relative "test_helper"

class DigestAlgorithmTest < Minitest::Test
  DA = EvidenceRecord::DigestAlgorithm

  def test_supported_algorithms
    assert_equal [[:sha256, "2.16.840.1.101.3.4.2.1", 32],
                  [:sha384, "2.16.840.1.101.3.4.2.2", 48],
                  [:sha512, "2.16.840.1.101.3.4.2.3", 64]],
                 DA::ALL.map { [_1.name, _1.oid, _1.digest_size] }
  end

  def test_fetch
    assert_same DA::SHA256, DA.fetch(:sha256)
    assert_same DA::SHA512, DA.fetch(DA::SHA512)
    assert_same DA::SHA384, DA.from_oid("2.16.840.1.101.3.4.2.2")
  end

  def test_unsupported
    assert_raises(EvidenceRecord::UnsupportedAlgorithmError) { DA.fetch(:sha1) }
    assert_raises(EvidenceRecord::UnsupportedAlgorithmError) { DA.fetch(:sha3_256) }
    assert_raises(EvidenceRecord::UnsupportedAlgorithmError) { DA.from_oid("1.3.14.3.2.26") } # SHA-1
    assert_raises(ArgumentError) { DA.fetch("sha256") }
  end

  def test_digest_concatenates_parts
    assert_equal OpenSSL::Digest.digest("SHA256", "abcdef"), DA::SHA256.digest("ab", "cd", "ef")
    assert_equal OpenSSL::Digest.digest("SHA512", ""), DA::SHA512.digest
    DA::ALL.each { |a| assert_equal a.digest_size, a.digest("x").bytesize }
  end

  def test_to_s
    assert_equal "sha256", DA::SHA256.to_s
  end
end
