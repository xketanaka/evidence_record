# frozen_string_literal: true

require_relative "test_helper"
require_relative "support/test_tsa"

class TimestampRenewalTest < Minitest::Test
  include VectorHelper

  ER = EvidenceRecord
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

  def renew(record, **request_options)
    renewal = record.timestamp_renewal
    renewal.build(respond(renewal, **request_options).to_der)
  end

  def timestamps(record)
    record.chains.last.archive_timestamps.map(&:timestamp)
  end

  # --- renewing ------------------------------------------------------------------------

  def test_first_renewal_covers_the_time_stamp_directly
    record, = records("a", "b")
    renewed = renew(record)
    assert_equal 1, renewed.chains.size
    first, second = renewed.chains[0].archive_timestamps
    assert_equal record.chains[0].archive_timestamps[0], first
    assert_nil second.reduced_hashtree
    assert_nil second.declared_digest_algorithm_oid
    assert_equal ER::Digest.new(h(first.timestamp.to_der)), second.timestamp.message_imprint
    assert renewed.verify!(data: "a", timestamp_validator: @validator)
    refute renewed.verify(data: "b", timestamp_validator: @validator)
  end

  # Later renewals cover all the time-stamps of the chain as one data group
  # (as Bouncy Castle does).
  def test_later_renewals_cover_all_time_stamps_of_the_chain
    record, = records("a", "b", digest_algorithm: :sha384)
    renewed = renew(renew(renew(record)))
    atss = renewed.chains[0].archive_timestamps
    assert_equal 4, atss.size
    last = atss.last
    covered = atss[0..2].map { ER::Digest.new(h(_1.timestamp.to_der, "SHA384")) }
    assert_equal [covered.sort_by(&:to_binary)], last.reduced_hashtree.partial_hashtrees.map { _1.sort_by(&:to_binary) }
    assert_equal ER::DigestAlgorithm::SHA384.oid, last.declared_digest_algorithm_oid
    assert_equal "SHA384", last.timestamp.hash_algorithm.name.to_s.upcase
    assert renewed.verify!(data: "a", timestamp_validator: @validator)
    assert_equal [ER::DigestAlgorithm::SHA384], renewed.digest_algorithms
    assert_equal record.proven_time, renewed.proven_time
  end

  def test_renewal
    record, = records("a", "b")
    renewal = record.timestamp_renewal
    assert_same record, renewal.record
    assert_equal ER::DigestAlgorithm::SHA256, renewal.digest_algorithm
    assert_equal ER::Digest.new(h(timestamps(record)[0].to_der)), renewal.root
    req = renewal.timestamp_request(nonce: 7, policy_id: "1.2.3.4", cert_requested: false)
    assert_equal "SHA256", req.algorithm.upcase
    assert_equal renewal.root.to_binary, req.message_imprint
    assert_equal 7, req.nonce.to_i
    assert_equal "1.2.3.4", req.policy_id
    refute req.cert_requested?
    assert_match(/SHA-?256/i, renewal.inspect)
  end

  def test_build_without_a_request_and_openssl_response_objects
    record, = records("a", "b")
    renewal = record.timestamp_renewal
    response = @tsa.respond(@tsa.request(renewal.root.to_binary), gen_time: next_time)
    assert renewal.build(response).verify(data: "a", timestamp_validator: @validator)
  end

  # Records built from the same hash tree can be renewed with one response,
  # again and again.
  def test_related_records_share_the_response
    a, b = records("a", ER::DataGroup.new(%w[b1 b2]))
    2.times do
      renewal = a.timestamp_renewal
      response = respond(renewal, nonce: 42).to_der
      a = renewal.build(response)
      b = b.timestamp_renewal.build(response)
    end
    assert a.related_to?(b)
    assert_equal timestamps(a), timestamps(b)
    assert a.verify!(data: "a", timestamp_validator: @validator)
    assert b.verify!(data: ER::DataGroup.new(%w[b1 b2]), timestamp_validator: @validator)
  end

  def test_other_fields_are_kept
    record, = records("a")
    crypto_infos = DER.context(0, DER.sequence([DER.encode_oid("1.2.3"), "\x31\x00".b]))
    with_infos = ER::Record.from_der(ER::Record.encode([ER::AlgorithmIdentifier.encode(ER::DigestAlgorithm::SHA256)],
                                                       crypto_infos, nil, record.chains))
    renewed = renew(with_infos)
    assert_equal crypto_infos, renewed.crypto_infos
    assert_equal 2, renewed.chains[0].archive_timestamps.size
  end

  # --- records with several chains (BSI test vectors) -----------------------------------

  def test_renewing_the_last_chain_of_bsi_records
    require_bsi_vectors!
    dir = "Testdaten_ERS-Testool/rfc4998"
    data = BSIVectors.read("#{dir}/2Chains3ATS/BIN.bin")
    { "1Chain2ATS/BIN_ER.ers" => [1, 3, "SHA256"], "2Chains3ATS/BIN_ER.ers" => [2, 2, "SHA512"] }.each do |name, (chains, size, alg)|
      record = ER::Record.from_der(BSIVectors.read("#{dir}/#{name}"))
      renewal = record.timestamp_renewal
      covered = record.chains.last.archive_timestamps.map { h(_1.timestamp.to_der, alg) }
      assert_equal ER::ReducedHashtree.node_hash(renewal.digest_algorithm, covered), renewal.root.to_binary, name
      renewed = renewal.build(respond(renewal, gen_time: Time.now).to_der)
      assert_equal chains, renewed.chains.size, name
      assert_equal size, renewed.chains.last.archive_timestamps.size, name
      assert_equal record.chains[0...-1], renewed.chains[0...-1], name
      assert renewed.verify_hashes!(data: data), name
    end
  end

  # --- errors ----------------------------------------------------------------------------

  def test_response_must_match_the_renewal
    record, = records("a", "b")
    renewal = record.timestamp_renewal
    renewal.timestamp_request(nonce: 1)
    other = @tsa.respond(@tsa.request(h("x"), nonce: 1), gen_time: next_time).to_der
    assert_raises(ER::TimestampResponseError) { renewal.build(other) }
    no_nonce = @tsa.respond(@tsa.request(renewal.root.to_binary), gen_time: next_time).to_der
    e = assert_raises(ER::TimestampResponseError) { renewal.build(no_nonce) }
    assert_match(/nonce/, e.message)
  end

  def test_time_stamp_older_than_the_record_is_rejected
    record, = records("a", "b")
    renewal = record.timestamp_renewal
    old = respond(renewal, gen_time: timestamps(record)[0].gen_time - 1).to_der
    e = assert_raises(ER::TimestampResponseError) { renewal.build(old) }
    assert_match(/older/, e.message)
    same = respond(renewal, gen_time: timestamps(record)[0].gen_time).to_der
    assert renewal.build(same).verify_hashes(data: "a")
  end

  def test_record_without_time_stamps
    empty = ER::Record.from_der(ER::Record.encode([], nil, nil, []))
    assert_raises(ER::MalformedRecordError) { empty.timestamp_renewal }
    empty_chain = ER::Record.from_der(ER::Record.encode([], nil, nil, [ER::Chain.from_der(DER.sequence([]))]))
    assert_raises(ER::MalformedRecordError) { empty_chain.timestamp_renewal }
  end

  def test_unsupported_algorithm
    tst = ER::TimeStampToken.from_der(@tsa.token_der(h("a", "SHA1"), algorithm: "SHA1"))
    chain = ER::Chain.build([ER::ArchiveTimeStamp.build(timestamp: tst)])
    record = ER::Record.from_der(ER::Record.encode([], nil, nil, [chain]))
    assert_raises(ER::UnsupportedAlgorithmError) { record.timestamp_renewal }
  end

  def test_mixed_algorithms_in_the_last_chain
    first, = records("a", "b")
    sha512 = ER::TimeStampToken.from_der(@tsa.token_der(h("x", "SHA512"), algorithm: "SHA512", gen_time: next_time))
    chain = ER::Chain.build(first.chains[0].archive_timestamps + [ER::ArchiveTimeStamp.build(timestamp: sha512)])
    record = first.with_chains([chain])
    assert_raises(ER::MalformedRecordError) { record.timestamp_renewal }
  end
end
