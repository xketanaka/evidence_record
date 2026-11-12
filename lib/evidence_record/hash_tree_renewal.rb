# frozen_string_literal: true

module EvidenceRecord
  # A hash-tree renewal of a Record (RFC 4998 §5.2, docs/design.md 3.5): a
  # new chain, whose first time-stamp covers the data and all the older
  # chains, hashed with a new algorithm. Done before the hash algorithm in
  # use weakens.
  #
  #   renewal = record.hash_tree_renewal(data: "doc-a", digest_algorithm: :sha512)
  #   req     = renewal.timestamp_request(nonce: SecureRandom.random_number(2**64))
  #   res     = post_to_tsa(req.to_der)        # the TSA response, as a String
  #   record2 = renewal.build(res)             # => a new Record
  #
  # The new time-stamp covers H(H(d) + ha) for the data object d, where ha
  # is the hash of the ArchiveTimeStampSequence so far (both with the new
  # algorithm). For a data object group, it covers H(H(d_i) + ha) for each
  # member, as one group. The concatenation is in this fixed order, as
  # Bouncy Castle does (docs/design.md 3.5).
  #
  # The record is first checked against the data (Record#verify_hashes!), so
  # that a record is never renewed with the wrong data. The signatures of the
  # time-stamps are not checked; do that with Record#verify before renewing.
  #
  # See Renewal for #timestamp_request and #build.
  class HashTreeRenewal
    include Renewal

    # Internal: use Record#hash_tree_renewal.
    def initialize(record, data:, digest_algorithm:)
      algorithm = DigestAlgorithm.fetch(digest_algorithm)
      source = DataSource.wrap(data)
      Verifier.new(record, source).verify_hashes!
      ha = algorithm.digest(record.archive_timestamp_sequence_der)
      prepare(record, algorithm, source.member_digests(algorithm).map { algorithm.digest(_1, ha) })
    end

    private

    def renewed_chains(archive_timestamp)
      @record.chains + [Chain.build([archive_timestamp])]
    end
  end
end
