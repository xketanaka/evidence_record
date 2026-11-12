# frozen_string_literal: true

module EvidenceRecord
  # Internal: what TimestampRenewal and HashTreeRenewal share. The including
  # class sets @record, @digest_algorithm and @values (the hashes covered by
  # the new time-stamp, as one data object group) with #prepare, and
  # implements #renewed_chains(archive_timestamp).
  module Renewal
    attr_reader :record, :digest_algorithm, :root

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
    #
    # The signature of the time-stamp is not checked; verify the new record
    # for that.
    def build(response)
      timestamp = @exchange.token(response)
      last = @record.chains.last.archive_timestamps.last.timestamp
      if timestamp.gen_time < last.gen_time
        raise TimestampResponseError, "the time-stamp is older than the last time-stamp of the record"
      end

      @record.with_chains(renewed_chains(archive_timestamp(timestamp)))
    end

    def inspect
      "#<#{self.class.name} #{@digest_algorithm} root=#{@root.to_hex}>"
    end

    private

    def prepare(record, digest_algorithm, values)
      @record = record
      @digest_algorithm = digest_algorithm
      @tree = HashTree.new(digest_algorithm: digest_algorithm)
      @tree.add(values)
      @single = values.size == 1
      @root = @tree.root
      @exchange = TimestampExchange.new(digest_algorithm, @root)
    end

    # With a single hash to cover, the hash is the message imprint and no
    # reduced hash tree is needed. Otherwise the reduced hash tree is the one
    # partial hash tree holding the hashes. Both as Bouncy Castle does
    # (ERSArchiveTimeStampGenerator).
    def archive_timestamp(timestamp)
      return ArchiveTimeStamp.build(timestamp: timestamp) if @single

      ArchiveTimeStamp.build(timestamp: timestamp, reduced_hashtree: @tree.reduced_hashtree(0),
                             digest_algorithm: @digest_algorithm)
    end
  end
end
