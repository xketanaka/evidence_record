# frozen_string_literal: true

module EvidenceRecord
  # A time-stamp renewal of a Record (RFC 4998 §5.2, docs/design.md 3.4):
  # a new ArchiveTimeStamp, added to the last chain, that covers the
  # time-stamps of that chain. Done before the time-stamps become invalid
  # (for example, before the TSA certificate expires).
  #
  #   renewal = record.timestamp_renewal
  #   req     = renewal.timestamp_request(nonce: SecureRandom.random_number(2**64))
  #   res     = post_to_tsa(req.to_der)        # the TSA response, as a String
  #   record2 = renewal.build(res)             # => a new Record
  #
  # The new time-stamp covers all the time-stamps of the last chain, as one
  # data object group, as Bouncy Castle does. Its hash algorithm is the one
  # of the last chain; when that algorithm weakens, use a hash-tree renewal
  # (HashTreeRenewal) instead.
  #
  # The data are not needed and the record is not verified. Records built
  # from the same hash tree and renewed in the same way have the same
  # time-stamps, so one TSA response can renew all of them: build a renewal
  # for each record and pass the same response to build.
  #
  # See Renewal for #timestamp_request and #build.
  class TimestampRenewal
    include Renewal

    # Internal: use Record#timestamp_renewal.
    def initialize(record)
      chain = record.chains.last
      if chain.nil? || chain.archive_timestamps.empty?
        raise MalformedRecordError, "the record has no ArchiveTimeStamp to renew"
      end

      oids = chain.archive_timestamps.map(&:digest_algorithm_oid).uniq
      raise MalformedRecordError, "hash algorithms are mixed within the last chain" unless oids.size == 1

      @chain = chain
      algorithm = DigestAlgorithm.from_oid(oids[0])
      prepare(record, algorithm, chain.archive_timestamps.map { algorithm.digest(_1.timestamp.to_der) })
    end

    private

    def renewed_chains(archive_timestamp)
      @record.chains[0...-1] + [Chain.build(@chain.archive_timestamps + [archive_timestamp])]
    end
  end
end
