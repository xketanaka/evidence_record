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
  # instead.
  #
  # The data are not needed and the record is not verified. Records built
  # from the same hash tree and renewed in the same way have the same
  # time-stamps, so one TSA response can renew all of them: build a renewal
  # for each record and pass the same response to build.
  #
  # build checks that the response is granted and matches the request, but
  # does not check its signature; verify the new record for that.
  class TimestampRenewal
    attr_reader :record, :digest_algorithm, :root

    # Internal: use Record#timestamp_renewal.
    def initialize(record)
      chain = record.chains.last
      if chain.nil? || chain.archive_timestamps.empty?
        raise MalformedRecordError, "the record has no ArchiveTimeStamp to renew"
      end

      oids = chain.archive_timestamps.map(&:digest_algorithm_oid).uniq
      raise MalformedRecordError, "hash algorithms are mixed within the last chain" unless oids.size == 1

      @record = record
      @chain = chain
      @digest_algorithm = DigestAlgorithm.from_oid(oids[0])
      @tree = HashTree.new(digest_algorithm: @digest_algorithm)
      @tree.add(chain.archive_timestamps.map { @digest_algorithm.digest(_1.timestamp.to_der) })
      @root = @tree.root
      @exchange = TimestampExchange.new(@digest_algorithm, @root)
    end

    # An OpenSSL::Timestamp::Request for the root, to be sent to a TSA. When
    # nonce or policy_id is given, build checks that the response has the
    # same values.
    def timestamp_request(nonce: nil, cert_requested: true, policy_id: nil)
      @exchange.request(nonce: nonce, cert_requested: cert_requested, policy_id: policy_id)
    end

    # Builds the renewed Record from the TSA response (a String, or an
    # OpenSSL::Timestamp::Response). Raises TimestampResponseError when the
    # response is not usable, including when its time-stamp is older than
    # the last one of the record.
    def build(response)
      timestamp = @exchange.token(response)
      last = @chain.archive_timestamps.last.timestamp
      if timestamp.gen_time < last.gen_time
        raise TimestampResponseError, "the time-stamp is older than the last time-stamp of the record"
      end

      chain = Chain.build(@chain.archive_timestamps + [archive_timestamp(timestamp)])
      @record.with_chains(@record.chains[0...-1] + [chain])
    end

    def inspect
      "#<#{self.class.name} #{@digest_algorithm} root=#{@root.to_hex}>"
    end

    private

    # With a single time-stamp to cover, its hash is the message imprint and
    # no reduced hash tree is needed (as Bouncy Castle does).
    def archive_timestamp(timestamp)
      return ArchiveTimeStamp.build(timestamp: timestamp) if @chain.archive_timestamps.size == 1

      ArchiveTimeStamp.build(timestamp: timestamp, reduced_hashtree: @tree.reduced_hashtree(0),
                             digest_algorithm: @digest_algorithm)
    end
  end
end
