# frozen_string_literal: true

require_relative "test_helper"
require_relative "support/test_tsa"

class HashTreeRenewalTest < Minitest::Test
  include VectorHelper

  ER = EvidenceRecord
  DA = EvidenceRecord::DigestAlgorithm
  DER = EvidenceRecord::DER

  def setup
    @tsa = TestTSA.default
    @validator = ER::TimestampValidator::OpenSSL.new(store: @tsa.store)
    @time = Time.now - 600
  end

  def h(data, alg = "SHA256")
    OpenSSL::Digest.digest(alg, data)
  end

  # Time-stamps are made one minute apart.
  def next_time
    @time += 60
  end

  def records(*items, digest_algorithm: :sha256)
    gen = ER::Generator.new(digest_algorithm: digest_algorithm)
    items.each { gen.add(_1) }
    gen.build(@tsa.respond(gen.timestamp_request, gen_time: next_time))
  end

  def respond(renewal, gen_time: next_time, **request_options)
    @tsa.respond(renewal.timestamp_request(**request_options), gen_time: gen_time)
  end

  def renew(record, data, alg, **request_options)
    renewal = record.hash_tree_renewal(data: data, digest_algorithm: alg)
    renewal.build(respond(renewal, **request_options).to_der)
  end

  # --- renewing ------------------------------------------------------------------------

  def test_data_object
    record, = records("a", "b")
    renewal = record.hash_tree_renewal(data: "a", digest_algorithm: :sha512)
    assert_same record, renewal.record
    assert_equal DA::SHA512, renewal.digest_algorithm
    ha = h(record.archive_timestamp_sequence_der, "SHA512")
    assert_equal ER::Digest.new(h(h("a", "SHA512") + ha, "SHA512")), renewal.root
    req = renewal.timestamp_request(nonce: 5)
    assert_equal "SHA512", req.algorithm.upcase
    assert_equal renewal.root.to_binary, req.message_imprint

    renewed = renewal.build(@tsa.respond(req, gen_time: next_time).to_der)
    assert_equal record.chains, renewed.chains[0, 1]
    ats = renewed.chains[1].archive_timestamps
    assert_equal 1, ats.size
    assert_nil ats[0].reduced_hashtree
    assert_nil ats[0].declared_digest_algorithm_oid
    assert_equal [DA::SHA256, DA::SHA512], renewed.digest_algorithms
    assert renewed.verify!(data: "a", timestamp_validator: @validator)
    refute renewed.verify(data: "b", timestamp_validator: @validator)
    assert_equal record.proven_time, renewed.proven_time
  end

  def test_data_group
    group = ER::DataGroup.new(%w[m1 m2 m3])
    record, = records(group, "x", digest_algorithm: :sha384)
    renewed = renew(record, group, :sha512)
    ats = renewed.chains[1].archive_timestamps[0]
    ha = h(record.archive_timestamp_sequence_der, "SHA512")
    expected = %w[m1 m2 m3].map { ER::Digest.new(h(h(_1, "SHA512") + ha, "SHA512")) }
    assert_equal [expected.sort_by(&:to_binary)], ats.reduced_hashtree.partial_hashtrees.map { _1.sort_by(&:to_binary) }
    assert_equal DA::SHA512.oid, ats.declared_digest_algorithm_oid
    assert renewed.verify!(data: group, timestamp_validator: @validator)
    refute renewed.verify(data: ER::DataGroup.new(%w[m1 zz]), timestamp_validator: @validator)
  end

  def test_prehashed_data_needs_both_algorithms
    record, = records("a", "b")
    old_only = ER::PrehashedData.new(sha256: h("a"))
    assert_raises(ArgumentError) { record.hash_tree_renewal(data: old_only, digest_algorithm: :sha512) }
    both = ER::PrehashedData.new(sha256: h("a"), sha512: h("a", "SHA512"))
    renewed = renew(record, both, :sha512)
    assert renewed.verify!(data: "a", timestamp_validator: @validator)
    assert renewed.verify!(data: both, timestamp_validator: @validator)
  end

  # Hash-tree and time-stamp renewals in turn, ending with the same
  # algorithm as before (allowed; digestAlgorithms lists it once).
  def test_renewals_in_turn
    record, = records("a", "b")
    record = renew(record, "a", :sha384)
    renewal = record.timestamp_renewal
    record = renewal.build(respond(renewal).to_der)
    record = renew(record, "a", :sha512)
    record = renew(record, "a", :sha256)
    assert_equal [1, 2, 1, 1], record.chains.map { _1.archive_timestamps.size }
    assert_equal [DA::SHA256, DA::SHA384, DA::SHA512], record.digest_algorithms
    assert record.verify!(data: "a", timestamp_validator: @validator)
    refute record.verify(data: "b", timestamp_validator: @validator)
  end

  def test_other_fields_are_kept
    record, = records("a")
    crypto_infos = DER.context(0, DER.sequence([DER.encode_oid("1.2.3"), "\x31\x00".b]))
    with_infos = ER::Record.from_der(ER::Record.encode([ER::AlgorithmIdentifier.encode(DA::SHA256)],
                                                       crypto_infos, nil, record.chains))
    renewed = renew(with_infos, "a", :sha512)
    assert_equal crypto_infos, renewed.crypto_infos
    assert renewed.verify!(data: "a", timestamp_validator: @validator)
  end

  # --- BSI test vectors ------------------------------------------------------------------

  # The second chains of these records are hash-tree renewals of
  # 1Chain2ATS/BIN_ER.ers with SHA-512. testRenewal.ers renewed the data
  # alone, so its time-stamp covers exactly our root; 2Chains3ATS renewed
  # it in a tree with other data, so our root is one of its leaves.
  def test_bsi_hash_tree_renewals
    require_bsi_vectors!
    dir = "Testdaten_ERS-Testool/rfc4998"
    record = ER::Record.from_der(BSIVectors.read("#{dir}/1Chain2ATS/BIN_ER.ers"))
    data = BSIVectors.read("#{dir}/1Chain2ATS/BIN.bin")
    root = record.hash_tree_renewal(data: data, digest_algorithm: :sha512).root

    renewed = ER::Record.from_der(BSIVectors.read("#{dir}/1Chain2ATS/testRenewal.ers"))
    assert_equal record.chains, renewed.chains[0, 1]
    assert_equal root, renewed.chains[1].archive_timestamps[0].timestamp.message_imprint

    renewed = ER::Record.from_der(BSIVectors.read("#{dir}/2Chains3ATS/BIN_ER.ers"))
    assert_equal record.chains, renewed.chains[0, 1]
    assert_includes renewed.chains[1].archive_timestamps[0].reduced_hashtree.leaf_values, root
  end

  # --- errors ----------------------------------------------------------------------------

  def test_data_must_match_the_record
    record, = records("a", "b")
    e = assert_raises(ER::HashMismatchError) { record.hash_tree_renewal(data: "c", digest_algorithm: :sha512) }
    assert_equal [0, 0], [e.chain_index, e.ats_index]
    renewed = renew(record, "a", :sha512)
    assert_raises(ER::HashMismatchError) { renewed.hash_tree_renewal(data: "b", digest_algorithm: :sha384) }
  end

  def test_malformed_records
    empty = ER::Record.from_der(ER::Record.encode([], nil, nil, []))
    assert_raises(ER::MalformedRecordError) { empty.hash_tree_renewal(data: "a", digest_algorithm: :sha512) }
  end

  def test_arguments
    record, = records("a", "b")
    assert_raises(ER::UnsupportedAlgorithmError) { record.hash_tree_renewal(data: "a", digest_algorithm: :sha1) }
    assert_raises(ArgumentError) { record.hash_tree_renewal(data: "a", digest_algorithm: "sha512") }
    assert_raises(ArgumentError) { record.hash_tree_renewal(data: 1, digest_algorithm: :sha512) }
    assert_raises(ArgumentError) { record.hash_tree_renewal(data: "a") }
  end

  def test_response_checks
    record, = records("a", "b")
    renewal = record.hash_tree_renewal(data: "a", digest_algorithm: :sha512)
    renewal.timestamp_request
    other = @tsa.respond(@tsa.request(h("a", "SHA512"), algorithm: "SHA512"), gen_time: next_time).to_der
    assert_raises(ER::TimestampResponseError) { renewal.build(other) }
    sha256 = @tsa.respond(@tsa.request(h("a")), gen_time: next_time).to_der
    assert_raises(ER::TimestampResponseError) { renewal.build(sha256) }
    old = respond(renewal, gen_time: record.proven_time - 1).to_der
    e = assert_raises(ER::TimestampResponseError) { renewal.build(old) }
    assert_match(/older/, e.message)
  end
end
