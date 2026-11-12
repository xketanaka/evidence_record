# frozen_string_literal: true

require_relative "test_helper"
require_relative "support/test_tsa"

class VerifyTest < Minitest::Test
  include VectorHelper

  ER = EvidenceRecord
  DA = EvidenceRecord::DigestAlgorithm

  def setup
    @tsa = TestTSA.default
    @validator = ER::TimestampValidator::OpenSSL.new(store: @tsa.store)
    @time = Time.now - 600
  end

  def h(data, alg = DA::SHA256)
    alg.digest(data)
  end

  # Time-stamps are made one minute apart.
  def next_time
    @time += 60
  end

  def token(imprint, alg = DA::SHA256)
    ER::TimeStampToken.from_der(@tsa.token_der(imprint, algorithm: alg.name.to_s.upcase, gen_time: next_time))
  end

  # Records for each of leaves (Strings or Arrays for data groups), built
  # by hand as the generator will build them (docs/design.md 4.2).
  def build_records(leaves, alg = DA::SHA256)
    tree = ER::HashTree.new(digest_algorithm: alg.name)
    leaves.each { |l| tree.add(Array(l).map { h(_1, alg) }) }
    tst = token(tree.root.to_binary, alg)
    leaves.each_index.map do |i|
      single = leaves.size == 1 && !leaves[0].is_a?(Array)
      ats = if single
              ER::ArchiveTimeStamp.build(timestamp: tst)
            else
              ER::ArchiveTimeStamp.build(timestamp: tst, reduced_hashtree: tree.reduced_hashtree(i), digest_algorithm: alg)
            end
      ER::Record.build([ER::Chain.build([ats])])
    end
  end

  # A time-stamp renewal: a new ArchiveTimeStamp covering the previous
  # time-stamp, added to the last chain.
  def renew_timestamp(record)
    chains = record.chains
    last = chains.last
    alg = last.archive_timestamps[0].digest_algorithm
    ats = ER::ArchiveTimeStamp.build(timestamp: token(h(last.archive_timestamps.last.timestamp.to_der, alg), alg))
    record.with_chains(chains[0...-1] + [ER::Chain.build(last.archive_timestamps + [ats])])
  end

  # A hash-tree renewal of a single data object with a new chain.
  def renew_hash_tree(record, data, alg, sorted: false)
    ha = h(record.archive_timestamp_sequence_der, alg)
    parts = [h(data, alg), ha]
    leaf = h((sorted ? parts.sort : parts).join, alg)
    ats = ER::ArchiveTimeStamp.build(timestamp: token(leaf, alg))
    record.with_chains(record.chains + [ER::Chain.build([ats])])
  end

  def assert_fails(error, record, data, chain_index: nil, ats_index: nil, validator: @validator, at: Time.now)
    refute record.verify(data: data, timestamp_validator: validator, at: at)
    e = assert_raises(error) { record.verify!(data: data, timestamp_validator: validator, at: at) }
    assert_equal [chain_index, ats_index], [e.chain_index, e.ats_index], e.message
    e
  end

  # --- records built here ------------------------------------------------------------

  def test_single_data_object
    record = build_records(["doc"])[0]
    assert_nil record.chains[0].archive_timestamps[0].reduced_hashtree
    assert record.verify(data: "doc", timestamp_validator: @validator)
    assert record.verify_hashes(data: "doc")
    refute record.verify_hashes(data: "other")
    assert_fails(ER::HashMismatchError, record, "other", chain_index: 0, ats_index: 0)
  end

  def test_tree_with_groups
    leaves = ["a", %w[g1 g2 g3], "c", "d", "e"]
    records = build_records(leaves, DA::SHA384)
    records.each_with_index do |record, i|
      data = leaves[i].is_a?(Array) ? ER::DataGroup.new(leaves[i]) : leaves[i]
      assert record.verify(data: data, timestamp_validator: @validator), "leaf #{i}"
      refute record.verify_hashes(data: "x")
    end
    # one member of a group alone is also covered
    assert records[1].verify_hashes(data: "g2")
    refute records[1].verify_hashes(data: ER::DataGroup.new(%w[g1 g2 x]))
  end

  def test_prehashed_data
    record = build_records(%w[a b])[1]
    assert record.verify(data: ER::PrehashedData.new(sha256: h("b")), timestamp_validator: @validator)
    refute record.verify(data: ER::PrehashedData.new(sha256: h("a")), timestamp_validator: @validator)
    assert_raises(ArgumentError) do
      record.verify(data: ER::PrehashedData.new(sha512: h("b", DA::SHA512)), timestamp_validator: @validator)
    end
  end

  def test_timestamp_renewal
    record = renew_timestamp(renew_timestamp(build_records(%w[a b c])[2]))
    assert_equal [3], record.chains.map { _1.archive_timestamps.size }
    assert record.verify(data: "c", timestamp_validator: @validator)
  end

  def test_hash_tree_renewal_in_both_orders
    data = (1..).lazy.map { "doc#{_1}" }.find do |d|
      # make sure the two orders give different hashes
      record = build_records([d])[0]
      h(d, DA::SHA512) > h(record.archive_timestamp_sequence_der, DA::SHA512)
    end
    base = renew_timestamp(build_records([data])[0])
    [false, true].each do |sorted|
      record = renew_timestamp(renew_hash_tree(base, data, DA::SHA512, sorted: sorted))
      assert_equal [DA::SHA256, DA::SHA512], record.digest_algorithms
      assert record.verify(data: data, timestamp_validator: @validator), "sorted: #{sorted}"
      assert record.verify(data: ER::PrehashedData.new(sha256: h(data), sha512: h(data, DA::SHA512)),
                           timestamp_validator: @validator)
      assert_raises(ArgumentError) do
        record.verify(data: ER::PrehashedData.new(sha256: h(data)), timestamp_validator: @validator)
      end
      assert_fails(ER::HashMismatchError, record, "other", chain_index: 0, ats_index: 0)
    end
  end

  def test_every_chain_is_checked_against_the_data
    record = build_records(["a"])[0]
    # a second chain over other data, linked correctly to the first chain
    other = renew_hash_tree(record, "b", DA::SHA512)
    assert_fails(ER::HashMismatchError, other, "a", chain_index: 1, ats_index: 0)
  end

  # --- structure ------------------------------------------------------------------------

  def test_empty_record_and_chain
    record = build_records(["a"])[0]
    assert_fails(ER::MalformedRecordError, record.with_chains([]), "a")
    assert_fails(ER::MalformedRecordError, record.with_chains([ER::Chain.build([])]), "a", chain_index: 0)
  end

  def test_mixed_algorithms_in_a_chain
    record = build_records(["a"])[0]
    first = record.chains[0].archive_timestamps[0]
    ats = ER::ArchiveTimeStamp.build(timestamp: token(h(first.timestamp.to_der, DA::SHA512), DA::SHA512))
    mixed = record.with_chains([ER::Chain.build([first, ats])])
    e = assert_fails(ER::MalformedRecordError, mixed, "a", chain_index: 0, ats_index: 1)
    assert_match(/mixed/, e.message)
  end

  def test_digest_algorithm_must_match_the_time_stamp
    tst = token(h("a"))
    ats = ER::ArchiveTimeStamp.build(timestamp: tst, digest_algorithm: DA::SHA512,
                                     reduced_hashtree: ER::ReducedHashtree.new([[h("a")]]))
    record = ER::Record.build([ER::Chain.build([ats])])
    assert_fails(ER::MalformedRecordError, record, "a", chain_index: 0, ats_index: 0)
  end

  def test_hash_lengths_in_the_reduced_hash_tree
    rht = ER::ReducedHashtree.new([[h("a"), "short"]])
    ats = ER::ArchiveTimeStamp.build(timestamp: token(rht.root(:sha256).to_binary), reduced_hashtree: rht)
    record = ER::Record.build([ER::Chain.build([ats])])
    assert_fails(ER::MalformedRecordError, record, "a", chain_index: 0, ats_index: 0)
  end

  def test_root_mismatch
    rht = ER::ReducedHashtree.new([[h("a"), h("b")]])
    ats = ER::ArchiveTimeStamp.build(timestamp: token(h("something else")), reduced_hashtree: rht)
    record = ER::Record.build([ER::Chain.build([ats])])
    e = assert_fails(ER::HashMismatchError, record, "a", chain_index: 0, ats_index: 0)
    assert_match(/root/, e.message)
  end

  def test_unsupported_algorithm_is_raised
    tst = ER::TimeStampToken.from_der(@tsa.token_der(OpenSSL::Digest.digest("SHA1", "a"), algorithm: "SHA1"))
    ats = ER::ArchiveTimeStamp.build(timestamp: tst)
    der = ER::DER.sequence([ER::DER.encode_integer(1), ER::DER.sequence([]),
                            ER::DER.sequence([ER::DER.sequence([ats.to_der])])])
    record = ER::Record.from_der(der)
    assert_raises(ER::UnsupportedAlgorithmError) { record.verify(data: "a", timestamp_validator: @validator) }
  end

  # --- times and time-stamp validation ----------------------------------------------

  def test_time_stamps_must_be_in_order
    record = build_records(["a"])[0]
    first = record.chains[0].archive_timestamps[0]
    @time -= 3600
    ats = ER::ArchiveTimeStamp.build(timestamp: token(h(first.timestamp.to_der)))
    reversed = record.with_chains([ER::Chain.build([first, ats])])
    assert reversed.verify_hashes(data: "a")
    assert_fails(ER::MalformedRecordError, reversed, "a", chain_index: 0, ats_index: 1)
  end

  def test_verification_time_before_the_last_time_stamp
    record = build_records(["a"])[0]
    assert_fails(ER::TimestampInvalidError, record, "a", chain_index: 0, ats_index: 0, at: @time - 1)
  end

  def test_validator_reference_times
    record = renew_timestamp(renew_hash_tree(renew_timestamp(build_records(["a"])[0]), "a", DA::SHA512))
    calls = []
    validator = lambda do |token, at:|
      calls << [token.gen_time, at]
      true
    end
    at = Time.now
    assert record.verify(data: "a", timestamp_validator: validator, at: at)
    gen_times = record.chains.flat_map(&:archive_timestamps).map { _1.timestamp.gen_time }
    assert_equal gen_times.zip(gen_times[1..] + [at]), calls
  end

  def test_validator_rejections
    record = renew_timestamp(build_records(["a"])[0])
    rejecting_second = lambda do |token, at:|
      _ = at
      raise ER::TimestampInvalidError, "revoked" if token == record.chains[0].archive_timestamps[1].timestamp

      true
    end
    e = assert_fails(ER::TimestampInvalidError, record, "a", chain_index: 0, ats_index: 1, validator: rejecting_second)
    assert_match(/revoked/, e.message)
    assert_kind_of ER::TimestampInvalidError, e.cause

    # returning false or nil also rejects
    assert_fails(ER::TimestampInvalidError, record, "a", chain_index: 0, ats_index: 0, validator: ->(_t, at:) { at && nil })
    # other errors are not swallowed
    assert_raises(RuntimeError) do
      record.verify(data: "a", timestamp_validator: ->(_t, at:) { raise "bug #{at}" })
    end
  end

  def test_openssl_validator
    record = build_records(["a"])[0]
    untrusted = ER::TimestampValidator::OpenSSL.new(store: OpenSSL::X509::Store.new)
    assert_fails(ER::TimestampInvalidError, record, "a", chain_index: 0, ats_index: 0, validator: untrusted)
    # the TSA certificate is not yet valid
    other_tsa = TestTSA.new(now: Time.now + (2 * 24 * 3600))
    future = ER::TimestampValidator::OpenSSL.new(store: other_tsa.store)
    tst = ER::TimeStampToken.from_der(other_tsa.token_der(h("a"), gen_time: Time.now))
    assert_raises(ER::TimestampInvalidError) { future.call(tst, at: Time.now) }
    future.call(tst, at: Time.now + (3 * 24 * 3600))
    assert_raises(ArgumentError) { ER::TimestampValidator::OpenSSL.new(store: nil) }
  end

  def test_argument_errors
    record = build_records(["a"])[0]
    assert_raises(ArgumentError) { record.verify(data: 1, timestamp_validator: @validator) }
    assert_raises(ArgumentError) { record.verify(data: "a", timestamp_validator: nil) }
    assert_raises(ArgumentError) { record.verify(data: "a", timestamp_validator: @validator, at: "now") }
  end

  # --- BSI test vectors -----------------------------------------------------------------

  # A validator trusting the self-signed certificates included in the tokens
  # of record (the test vectors' TSA roots).
  def bsi_validator(record)
    certs = record.chains.flat_map(&:archive_timestamps).flat_map { _1.timestamp.certificates }
    store = OpenSSL::X509::Store.new
    certs.select { _1.subject.to_s == _1.issuer.to_s }.uniq(&:to_der).each { store.add_cert(_1) }
    ER::TimestampValidator::OpenSSL.new(store: store)
  end

  def bsi_record(relative)
    ER::Record.from_der(BSIVectors.read(relative))
  end

  def last_gen_time(record)
    record.chains.last.archive_timestamps.last.timestamp.gen_time
  end

  def test_bsi_ers_testtool
    require_bsi_vectors!
    %w[1Chain1ATS/BIN_ER.ers 1Chain2ATS/BIN_ER.ers 1Chain2ATS/testRenewal.ers 2Chains3ATS/BIN_ER.ers].each do |name|
      dir = "Testdaten_ERS-Testool/rfc4998/#{name.split('/')[0]}"
      record = bsi_record("Testdaten_ERS-Testool/rfc4998/#{name}")
      data = BSIVectors.read("#{dir}/BIN.bin")
      at = last_gen_time(record) + 60
      assert record.verify!(data: data, timestamp_validator: bsi_validator(record), at: at), name
      refute record.verify(data: "#{data}x", timestamp_validator: bsi_validator(record), at: at), name
    end
  end

  # The TR-ESOR C.2 records cover a data group of two documents that are not
  # in the test data; their hashes are taken from ER_OK_INIT. The second
  # chain of the *_SEQ records uses SHA-384 and cannot be checked without the
  # documents.
  def test_bsi_tr_esor
    require_bsi_vectors!
    dir = "BSI TR-ESOR C.2 TestData"
    ok = bsi_record("#{dir}/ER_OK_INIT.ers")
    group = ER::DataGroup.new(ok.chains[0].archive_timestamps[0].reduced_hashtree.leaf_values.map do
      ER::PrehashedData.new(sha256: _1)
    end)
    validator = bsi_validator(ok)
    verify = lambda do |name|
      record = bsi_record("#{dir}/#{name}.ers")
      record.verify!(data: group, timestamp_validator: validator, at: last_gen_time(record) + 60)
    end
    assert verify.("ER_OK_INIT")
    assert verify.("ER_OK_CHAIN")
    e = assert_raises(ER::HashMismatchError) { verify.("ER_NOK_INIT") }
    assert_equal [0, 0], [e.chain_index, e.ats_index]
    e = assert_raises(ER::HashMismatchError) { verify.("ER_NOK_CHAIN") }
    assert_equal [0, 1], [e.chain_index, e.ats_index]
    assert_raises(ArgumentError) { verify.("ER_OK_SEQ") } # needs the SHA-384 hashes of the documents
  end
end
