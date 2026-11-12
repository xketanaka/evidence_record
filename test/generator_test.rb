# frozen_string_literal: true

require_relative "test_helper"
require_relative "support/test_tsa"

class GeneratorTest < Minitest::Test
  include VectorHelper

  ER = EvidenceRecord
  DER = EvidenceRecord::DER

  def setup
    @tsa = TestTSA.default
    @validator = ER::TimestampValidator::OpenSSL.new(store: @tsa.store)
  end

  def h(data, alg = "SHA256")
    OpenSSL::Digest.digest(alg, data)
  end

  def generator(*items, digest_algorithm: :sha256)
    gen = ER::Generator.new(digest_algorithm: digest_algorithm)
    items.each { gen.add(_1) }
    gen
  end

  def build(gen, **request_options)
    gen.build(@tsa.respond(gen.timestamp_request(**request_options)).to_der)
  end

  # --- building ------------------------------------------------------------------------

  def test_records_verify_in_add_order
    group = ER::DataGroup.new(%w[g1 g2])
    items = ["a", group, ER::PrehashedData.new(sha384: h("c", "SHA384")), "d", "e"]
    gen = generator(*items, digest_algorithm: :sha384)
    records = build(gen, nonce: 1234)
    assert_equal 5, records.size
    records.each_with_index do |record, i|
      assert record.verify!(data: items[i], timestamp_validator: @validator), "item #{i}"
      ats = record.chains[0].archive_timestamps[0]
      assert_equal ER::DigestAlgorithm::SHA384.oid, ats.declared_digest_algorithm_oid
      assert_equal gen.root, ats.reduced_hashtree.root(:sha384)
      assert_equal [ER::DigestAlgorithm::SHA384], record.digest_algorithms
      assert_equal record, ER::Record.from_der(record.to_der)
    end
    refute records[0].verify(data: "d", timestamp_validator: @validator)
    assert records.combination(2).all? { |a, b| a.related_to?(b) }
    assert_equal 1234, records[0].chains[0].archive_timestamps[0].timestamp.nonce
  end

  def test_single_data_object_has_no_reduced_hash_tree
    record, = build(generator("only"))
    ats = record.chains[0].archive_timestamps[0]
    assert_nil ats.reduced_hashtree
    assert_nil ats.declared_digest_algorithm_oid
    assert_equal ER::Digest.new(h("only")), ats.timestamp.message_imprint
    assert record.verify(data: "only", timestamp_validator: @validator)
  end

  def test_single_group_keeps_its_members
    group = ER::DataGroup.new(%w[m1 m2])
    record, = build(generator(group))
    assert_equal %w[m1 m2].map { ER::Digest.new(h(_1)) }.sort_by(&:to_binary),
                 record.chains[0].archive_timestamps[0].reduced_hashtree.leaf_values.sort_by(&:to_binary)
    assert record.verify(data: group, timestamp_validator: @validator)
  end

  def test_root_matches_bouncy_castle
    h3 = ["This is H3A", "This is H3B", "This is H3C"]
    gen = generator("This is H1", "This is H2", ER::DataGroup.new(h3))
    assert_equal "98fbf91c1aebdfec514d4a76532ec95f27ebcf4c8b6f7e2947afcbbfe7084cd4", gen.root.to_hex
  end

  def test_request
    gen = generator("a", "b", digest_algorithm: :sha512)
    req = gen.timestamp_request(nonce: 99, policy_id: "1.2.3.4")
    assert_equal "SHA512", req.algorithm.upcase
    assert_equal gen.root.to_binary, req.message_imprint
    assert_equal 99, req.nonce.to_i
    assert_equal "1.2.3.4", req.policy_id
    assert req.cert_requested?
    refute gen.timestamp_request(cert_requested: false).cert_requested?
    assert_raises(ArgumentError) { gen.timestamp_request(nonce: "1") }
    assert_raises(ArgumentError) { gen.timestamp_request(policy_id: :x) }
  end

  def test_accepts_openssl_response_objects
    gen = generator("a", "b")
    records = gen.build(@tsa.respond(gen.timestamp_request))
    assert records[1].verify(data: "b", timestamp_validator: @validator)
  end

  # --- state ----------------------------------------------------------------------------

  def test_no_data_after_the_request
    gen = generator("a")
    gen.timestamp_request
    assert_raises(ER::Error) { gen.add("b") }
    gen = generator("a")
    gen.build(@tsa.respond(@tsa.request(gen.root.to_binary)).to_der)
    assert_raises(ER::Error) { gen.add("b") }
  end

  def test_empty_generator
    gen = ER::Generator.new
    assert_equal 0, gen.size
    assert_raises(ER::Error) { gen.root }
    assert_raises(ER::Error) { gen.timestamp_request }
    gen.add("a") # still possible
    assert_equal 1, gen.size
  end

  def test_argument_errors
    assert_raises(ER::UnsupportedAlgorithmError) { ER::Generator.new(digest_algorithm: :sha1) }
    assert_raises(ArgumentError) { ER::Generator.new.add(1) }
    gen = generator("a")
    assert_raises(ArgumentError) { gen.build(nil) }
  end

  # --- checking the response ------------------------------------------------------------

  def assert_response_error(pattern, gen, response)
    e = assert_raises(ER::TimestampResponseError) { gen.build(response) }
    assert_match pattern, e.message
  end

  def test_rejected_response
    gen = generator("a")
    gen.timestamp_request
    rejected = @tsa.respond(@tsa.request(h("a", "SHA224")[0, 28], algorithm: "SHA224")).to_der
    assert_response_error(/rejected.*status 2.*not supported/, gen, rejected)
  end

  def test_response_for_other_data
    gen = generator("a")
    gen.timestamp_request
    assert_response_error(/imprint/, gen, @tsa.respond(@tsa.request(h("b"))).to_der)
    assert_response_error(/hash algorithm/, gen, @tsa.respond(@tsa.request(h("a", "SHA512"), algorithm: "SHA512")).to_der)
  end

  def test_nonce_and_policy_are_checked
    gen = generator("a", "b")
    gen.timestamp_request(nonce: 1)
    assert_response_error(/nonce/, gen, @tsa.respond(@tsa.request(gen.root.to_binary, nonce: 2)).to_der)
    assert_response_error(/nonce/, gen, @tsa.respond(@tsa.request(gen.root.to_binary)).to_der)

    gen.timestamp_request(policy_id: "1.2.3.4")
    other = @tsa.request(gen.root.to_binary)
    other.policy_id = "1.2.3.5"
    assert_response_error(/policy/, gen, @tsa.respond(other).to_der)
  end

  def test_malformed_responses
    gen = generator("a")
    gen.timestamp_request
    assert_response_error(/invalid/, gen, "not a response")
    no_token = DER.sequence([DER.sequence([DER.encode_integer(0)])])
    assert_response_error(/no time-stamp token/, gen, no_token)
    # not DER beyond its lengths: an INTEGER with a redundant leading byte
    bad_status = DER.sequence([DER.sequence(["\x02\x02\x00\x00".b]), DER.parse(@tsa.respond(@tsa.request(h("a"))).to_der, "x").children[1].raw])
    assert_response_error(/invalid/, gen, bad_status)
  end

  # --- BER responses ----------------------------------------------------------------------

  # Re-encodes the outer SEQUENCE and the ContentInfo of the token with
  # indefinite lengths, and the status with a long-form length.
  def ber_response(der)
    status, token = DER.parse(der, "x").children
    content_type, wrapper = token.children
    ber_token = "\x30\x80".b + content_type.raw + "\xa0\x80".b + wrapper.content + "\x00\x00\x00\x00".b
    ber_status = "\x30\x81".b + [status.content.bytesize].pack("C") + status.content
    "\x30\x80".b + ber_status + ber_token + "\x00\x00".b
  end

  def test_ber_lengths_are_rewritten_as_der
    gen = generator("a", "b")
    der = @tsa.respond(gen.timestamp_request).to_der
    records = gen.build(ber_response(der))
    assert_equal DER.parse(der, "x").children[1].raw, records[0].chains[0].archive_timestamps[0].timestamp.to_der
    assert records[0].verify(data: "a", timestamp_validator: @validator)
  end

  # The token in the BSI test vectors, as it came from the TSA (BER), is
  # stored in the Evidence Record with DER lengths.
  def test_bsi_ber_token
    require_bsi_vectors!
    dir = "Testdaten_ERS-Testool/rfc4998/2Chains3ATS"
    record = ER::Record.from_der(BSIVectors.read("#{dir}/BIN_ER.ers"))
    tokens = record.chains.flat_map(&:archive_timestamps).map(&:timestamp)
    %w[0.0 0.1 1.0].each_with_index do |suffix, i|
      tsr = BSIVectors.read("#{dir}/BIN_ER.ers.#{suffix}.tsr")
      assert_raises(ER::ParseError) { DER.parse(tsr, "x") }
      response = "\x30\x80\x30\x03\x02\x01\x00".b + tsr + "\x00\x00".b
      exchange = ER::TimestampExchange.new(tokens[i].hash_algorithm, tokens[i].message_imprint)
      assert_equal tokens[i], exchange.token(response), suffix
    end
  end
end
