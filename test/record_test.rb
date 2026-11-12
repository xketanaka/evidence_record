# frozen_string_literal: true

require_relative "test_helper"
require_relative "support/test_tsa"

class RecordTest < Minitest::Test
  include VectorHelper

  ER = EvidenceRecord
  DER = EvidenceRecord::DER
  SHA1_OID = "1.3.14.3.2.26"

  def h(data, alg = "SHA256")
    OpenSSL::Digest.digest(alg, data)
  end

  def tsa
    TestTSA.default
  end

  def token(imprint = h("data"), algorithm: "SHA256", gen_time: Time.now)
    ER::TimeStampToken.from_der(tsa.token_der(imprint, algorithm: algorithm, gen_time: gen_time))
  end

  def algorithm_der(oid, params = nil)
    DER.sequence([DER.encode_oid(oid), params].compact)
  end

  def implicit(tag, der)
    DER.context(tag, DER.parse(der, "x").content)
  end

  def record_der(chains_der, version: 1, algorithms: [algorithm_der(ER::DigestAlgorithm::SHA256.oid)], extra: [])
    DER.sequence([DER.encode_integer(version), DER.sequence(algorithms), *extra, chains_der])
  end

  def single_ats_record_der(ats_der, **opts)
    record_der(DER.sequence([DER.sequence([ats_der])]), **opts)
  end

  # --- reading the BSI test vectors ---------------------------------------------

  def test_reads_bsi_vectors_and_keeps_their_bytes
    require_bsi_vectors!
    BSIVectors::FILES.each_key.grep(/\.ers\z/).each do |relative|
      der = BSIVectors.read(relative)
      record = ER::Record.from_der(der)
      assert_equal der, record.to_der, relative
      assert_equal 1, record.version
      record.chains.each do |chain|
        assert der.include?(chain.to_der)
        chain.archive_timestamps.each do |ats|
          assert der.include?(ats.to_der)
          assert der.include?(ats.timestamp.to_der)
        end
      end
    end
  end

  def test_bsi_two_chains
    require_bsi_vectors!
    record = ER::Record.from_der(BSIVectors.read("Testdaten_ERS-Testool/rfc4998/2Chains3ATS/BIN_ER.ers"))
    assert_equal [ER::DigestAlgorithm::SHA256, ER::DigestAlgorithm::SHA512], record.digest_algorithms
    assert_equal [2, 1], record.chains.map { _1.archive_timestamps.size }
    ats = record.chains[1].archive_timestamps[0]
    assert_equal ER::DigestAlgorithm::SHA512, ats.digest_algorithm
    assert_equal ER::DigestAlgorithm::SHA512, ats.timestamp.hash_algorithm
    assert_equal [2, 1, 1], ats.reduced_hashtree.partial_hashtrees.map(&:size)
    # the fractional seconds of genTime are kept (Ruby's OpenSSL::ASN1 drops them)
    assert_equal Time.utc(2017, 2, 10, 14, 9, Rational(365, 10)), ats.timestamp.gen_time
    assert_equal [2017, 2, 10, 14, 7, 52], record.proven_time.to_a[0, 6].reverse
    assert_equal 2, ats.timestamp.certificates.size
    assert_kind_of OpenSSL::X509::Certificate, ats.timestamp.certificates[0]
  end

  # --- building --------------------------------------------------------------------

  def test_time_stamp_token_fields
    gen_time = Time.utc(2030, 1, 2, 3, 4, 5)
    tst = token(h("x", "SHA384"), algorithm: "SHA384", gen_time: gen_time)
    assert_equal gen_time, tst.gen_time
    assert_equal ER::Digest.new(h("x", "SHA384")), tst.message_imprint
    assert_equal ER::DigestAlgorithm::SHA384, tst.hash_algorithm
    assert_equal "1.3.6.1.4.1.99999.1", tst.policy_id
    assert_kind_of Integer, tst.serial_number
    assert_nil tst.nonce
    assert_equal [tsa.certificate.to_der, tsa.root.to_der], tst.certificates.map(&:to_der)
    assert_equal tst, ER::TimeStampToken.from_der(tst.to_der)
  end

  def test_build_archive_timestamp_with_reduced_hashtree
    rht = ER::ReducedHashtree.new([[h("a"), h("b")], [h("c")]])
    tst = token(rht.root(:sha256).to_binary)
    ats = ER::ArchiveTimeStamp.build(timestamp: tst, reduced_hashtree: rht, digest_algorithm: ER::DigestAlgorithm::SHA256)
    assert_equal rht, ats.reduced_hashtree
    assert_equal tst, ats.timestamp
    assert_equal ER::DigestAlgorithm::SHA256.oid, ats.declared_digest_algorithm_oid
    assert_equal ats, ER::ArchiveTimeStamp.from_der(ats.to_der)
    assert ats.frozen?
  end

  def test_build_archive_timestamp_without_optional_fields
    tst = token(h("a", "SHA512"), algorithm: "SHA512")
    ats = ER::ArchiveTimeStamp.build(timestamp: tst)
    assert_nil ats.reduced_hashtree
    assert_nil ats.declared_digest_algorithm_oid
    assert_equal ER::DigestAlgorithm::SHA512, ats.digest_algorithm # from the time-stamp
    assert_equal DER.sequence([tst.to_der]), ats.to_der
  end

  def test_build_record
    ats1 = ER::ArchiveTimeStamp.build(timestamp: token)
    ats2 = ER::ArchiveTimeStamp.build(timestamp: token(h("b", "SHA512"), algorithm: "SHA512"))
    record = ER::Record.build([ER::Chain.build([ats1]), ER::Chain.build([ats2])])
    assert_equal [ER::DigestAlgorithm::SHA256, ER::DigestAlgorithm::SHA512], record.digest_algorithms
    assert_equal [[ats1], [ats2]], record.chains.map(&:archive_timestamps)
    assert_equal record, ER::Record.from_der(record.to_der)
    assert_equal ats1.timestamp.gen_time, record.proven_time
    assert_nil record.crypto_infos
    assert_nil record.encryption_info
    assert_equal DER.sequence([record.chains[0].to_der]), record.archive_timestamp_sequence_der(1)
    assert_equal DER.parse(record.to_der, "x").children.last.raw, record.archive_timestamp_sequence_der
  end

  def test_related_to
    shared = ER::ArchiveTimeStamp.build(timestamp: token)
    a = ER::Record.build([ER::Chain.build([shared])])
    b = ER::Record.build([ER::Chain.build([shared, ER::ArchiveTimeStamp.build(timestamp: token)])])
    c = ER::Record.build([ER::Chain.build([ER::ArchiveTimeStamp.build(timestamp: token)])])
    assert a.related_to?(b)
    refute a.related_to?(c)
    assert_raises(ArgumentError) { a.related_to?(a.to_der) }
  end

  def test_with_chains_keeps_other_fields_and_adds_algorithms
    ats = ER::ArchiveTimeStamp.build(timestamp: token)
    crypto_infos = DER.context(0, DER.sequence([DER.encode_oid("1.2.3.4"), DER.encode(0x31, DER.encode_integer(1))]))
    encryption_info = DER.context(1, DER.encode_oid("1.2.3.5") + DER.encode_octet_string("x"))
    # NULL parameters, as in the BSI test vectors, are kept as they are
    sha256_null = algorithm_der(ER::DigestAlgorithm::SHA256.oid, "\x05\x00".b)
    chain = ER::Chain.build([ats])
    der = record_der(DER.sequence([chain.to_der]), algorithms: [sha256_null], extra: [crypto_infos, encryption_info])
    record = ER::Record.from_der(der)
    assert_equal crypto_infos, record.crypto_infos
    assert_equal encryption_info, record.encryption_info

    ats512 = ER::ArchiveTimeStamp.build(timestamp: token(h("x", "SHA512"), algorithm: "SHA512"))
    renewed = record.with_chains(record.chains + [ER::Chain.build([ats512])])
    assert_equal crypto_infos, renewed.crypto_infos
    assert_equal encryption_info, renewed.encryption_info
    assert_equal [ER::DigestAlgorithm::SHA256.oid, ER::DigestAlgorithm::SHA512.oid], renewed.digest_algorithm_oids
    assert renewed.to_der.include?(DER.sequence([sha256_null, algorithm_der(ER::DigestAlgorithm::SHA512.oid)]))
    assert_equal record, record.with_chains(record.chains)
  end

  def test_empty_structures_are_parsed
    # rejected by verification (MalformedRecordError), not by the parser
    assert_empty ER::Record.from_der(record_der(DER.sequence([]))).chains
    record = ER::Record.from_der(record_der(DER.sequence([DER.sequence([])])))
    assert_empty record.chains[0].archive_timestamps
    assert_nil record.proven_time
    refute record.related_to?(record)
  end

  # --- algorithms ----------------------------------------------------------------------

  def test_unknown_algorithms_are_readable
    tst = token
    ats_der = DER.sequence([implicit(0, algorithm_der(SHA1_OID)), tst.to_der])
    record = ER::Record.from_der(single_ats_record_der(ats_der, algorithms: [algorithm_der(SHA1_OID)]))
    assert_equal [SHA1_OID], record.digest_algorithm_oids
    assert_raises(ER::UnsupportedAlgorithmError) { record.digest_algorithms }
    ats = record.chains[0].archive_timestamps[0]
    assert_equal SHA1_OID, ats.digest_algorithm_oid
    assert_raises(ER::UnsupportedAlgorithmError) { ats.digest_algorithm }
  end

  def test_sha2_parameters_must_be_absent_or_null
    oid = ER::DigestAlgorithm::SHA256.oid
    ER::Record.from_der(single_ats_record_der(DER.sequence([token.to_der]),
                                              algorithms: [algorithm_der(oid, "\x05\x00".b)]))
    e = assert_raises(ER::ParseError) do
      ER::Record.from_der(single_ats_record_der(DER.sequence([token.to_der]),
                                                algorithms: [algorithm_der(oid, DER.encode_integer(1))]))
    end
    assert_match(/absent or NULL/, e.message)
  end

  def test_algorithm_identifiers_must_have_the_right_tag
    oid = DER.encode_oid(ER::DigestAlgorithm::SHA256.oid)
    tst = token.to_der
    ats = DER.sequence([tst])
    [DER.encode(0x31, oid), DER.context(5, oid)].each do |bad|
      # digestAlgorithms of the record
      assert_raises(ER::ParseError) { ER::Record.from_der(single_ats_record_der(ats, algorithms: [bad])) }
      # digestAlgorithm [0] of an ArchiveTimeStamp (a SEQUENCE is also wrong there)
      assert_raises(ER::ParseError) { ER::ArchiveTimeStamp.from_der(DER.sequence([bad, tst])) }
    end
    assert_raises(ER::ParseError) { ER::ArchiveTimeStamp.from_der(DER.sequence([DER.sequence([oid]), tst])) }
  end

  # --- invalid input -------------------------------------------------------------------

  def test_rejects_invalid_records
    ats = DER.sequence([token.to_der])
    chains = DER.sequence([DER.sequence([ats])])
    {
      "version 2" => record_der(chains, version: 2),
      "version 0" => record_der(chains, version: 0),
      "trailing element" => DER.sequence([DER.parse(record_der(chains), "x").content, DER.encode_integer(1)]),
      "missing sequence" => DER.sequence([DER.encode_integer(1), DER.sequence([])]),
      "cryptoInfos after encryptionInfo" => record_der(chains, extra: [DER.context(1, DER.encode_oid("1.2.3") + DER.encode_integer(1)),
                                                                     DER.context(0, DER.sequence([]))]),
      "empty cryptoInfos" => record_der(chains, extra: [DER.context(0, "")]),
      "chain is not a sequence" => record_der(DER.sequence([ats])),
    }.each do |name, der|
      assert_raises(ER::ParseError, name) { ER::Record.from_der(der) }
    end
  end

  def test_rejects_invalid_archive_timestamps
    tst = token.to_der
    rht_field = DER.context(2, DER.sequence([DER.encode_octet_string(h("a"))]))
    alg_field = implicit(0, algorithm_der(ER::DigestAlgorithm::SHA256.oid))
    {
      "fields out of order" => DER.sequence([rht_field, alg_field, tst]),
      "duplicate field" => DER.sequence([alg_field, alg_field, tst]),
      "empty reducedHashtree" => DER.sequence([DER.context(2, ""), tst]),
      "empty partial hash tree" => DER.sequence([DER.context(2, DER.sequence([])), tst]),
      "hash is not an OCTET STRING" => DER.sequence([DER.context(2, DER.sequence([DER.encode_integer(1)])), tst]),
      "no timeStamp" => DER.sequence([alg_field]),
      "timeStamp is not a ContentInfo" => DER.sequence([DER.encode_integer(1)]),
      "not SignedData" => DER.sequence([DER.sequence([DER.encode_oid("1.2.840.113549.1.7.1"),
                                                      DER.context(0, DER.encode_octet_string("x"))])]),
    }.each do |name, der|
      assert_raises(ER::ParseError, name) { ER::ArchiveTimeStamp.from_der(der) }
    end
  end

  # An unsigned token with the given TSTInfo fields, for testing the parser.
  def fake_token_der(imprint:, algorithm_oid: ER::DigestAlgorithm::SHA256.oid, algorithm_tag: 0x30,
                     gen_time: "20240102030405Z")
    algorithm = DER.encode(algorithm_tag, DER.encode_oid(algorithm_oid))
    tst_info = DER.sequence([DER.encode_integer(1), DER.encode_oid("1.2.3"),
                             DER.sequence([algorithm, DER.encode_octet_string(imprint)]),
                             DER.encode_integer(7), DER.encode(0x18, gen_time)])
    encap = DER.sequence([DER.encode_oid(ER::TimeStampToken::ID_CT_TST_INFO),
                          DER.context(0, DER.encode_octet_string(tst_info))])
    signed_data = DER.sequence([DER.encode_integer(3), DER.encode(0x31, ""), encap, DER.encode(0x31, "")])
    DER.sequence([DER.encode_oid(ER::TimeStampToken::ID_SIGNED_DATA), DER.context(0, signed_data)])
  end

  def test_fake_token_is_readable
    tst = ER::TimeStampToken.from_der(fake_token_der(imprint: h("x"), gen_time: "20240102030405.5Z"))
    assert_equal Time.utc(2024, 1, 2, 3, 4, 5.5), tst.gen_time
    assert_equal 7, tst.serial_number
    assert_empty tst.certificates
  end

  def test_rejects_imprint_of_wrong_length
    der = fake_token_der(imprint: h("x"), algorithm_oid: ER::DigestAlgorithm::SHA512.oid)
    e = assert_raises(ER::ParseError) { ER::TimeStampToken.from_der(der) }
    assert_match(/64 bytes/, e.message)
    # hashAlgorithm of messageImprint must be a SEQUENCE
    e = assert_raises(ER::ParseError) do
      ER::TimeStampToken.from_der(fake_token_der(imprint: h("x"), algorithm_tag: 0x31))
    end
    assert_match(/AlgorithmIdentifier/, e.message)
    # the length of an unknown algorithm's hash is not checked
    ER::TimeStampToken.from_der(fake_token_der(imprint: h("x"), algorithm_oid: SHA1_OID))
  end

  def test_rejects_invalid_tst_info
    assert_raises(ER::ParseError) { ER::TimeStampToken.from_der(fake_token_der(imprint: h("x"), gen_time: "20240102030405")) }
    assert_raises(ER::ParseError) { ER::TimeStampToken.from_der(fake_token_der(imprint: h("x"), gen_time: "20241302030405Z")) }
  end

  def test_rejects_non_der
    der = record_der(DER.sequence([DER.sequence([DER.sequence([token.to_der])])]))
    # re-encode the outer SEQUENCE with an indefinite length
    ber = "\x30\x80".b + DER.parse(der, "x").content + "\x00\x00".b
    assert_raises(ER::ParseError) { ER::Record.from_der(ber) }
    assert_raises(ER::ParseError) { ER::Record.from_der("") }
    assert_raises(ER::ParseError) { ER::Record.from_der("#{der}\x00") }
    assert_raises(ArgumentError) { ER::Record.from_der(nil) }
  end

  def test_constructors_are_internal
    assert_raises(NoMethodError) { ER::Record.new(nil) }
    assert_raises(NoMethodError) { ER::Chain.new(nil, "x") }
    assert_raises(NoMethodError) { ER::ArchiveTimeStamp.new(nil, "x") }
    assert_raises(NoMethodError) { ER::TimeStampToken.new(nil, "x") }
  end
end
