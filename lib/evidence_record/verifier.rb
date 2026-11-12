# frozen_string_literal: true

module EvidenceRecord
  # Internal: verifies a Record against data (docs/design.md 5.1). Used by
  # Record#verify!, #verify_hashes! and the renewals.
  class Verifier
    def initialize(record, data)
      @record = record
      @data = DataSource.wrap(data)
    end

    # Steps 1-3: the structure and the hash chain, without looking at the
    # signatures or the times of the time-stamps.
    def verify_hashes!
      check_structure!
      @record.chains.each_with_index { |chain, ci| verify_chain!(chain, ci) }
      true
    end

    # All steps.
    def verify!(timestamp_validator:, at:)
      verify_hashes!
      check_times!(at)
      validate_timestamps!(timestamp_validator, at)
      true
    end

    private

    # [ArchiveTimeStamp, chain index, index in chain] in chronological order.
    def entries
      @record.chains.each_with_index.flat_map do |chain, ci|
        chain.archive_timestamps.each_with_index.map { |ats, ai| [ats, ci, ai] }
      end
    end

    # Step 1.
    def check_structure!
      raise MalformedRecordError, "the record has no ArchiveTimeStampChain" if @record.chains.empty?

      @record.chains.each_with_index do |chain, ci|
        if chain.archive_timestamps.empty?
          raise MalformedRecordError.new("chain #{ci} has no ArchiveTimeStamp", chain_index: ci)
        end

        oid = chain.archive_timestamps[0].digest_algorithm_oid
        chain.archive_timestamps.each_with_index { |ats, ai| check_archive_timestamp!(ats, oid, ci, ai) }
      end
    end

    def check_archive_timestamp!(ats, chain_oid, ci, ai)
      where = { chain_index: ci, ats_index: ai }
      unless ats.digest_algorithm_oid == chain_oid
        raise MalformedRecordError.new("#{at(ci, ai)}: hash algorithms are mixed within a chain", **where)
      end
      declared = ats.declared_digest_algorithm_oid
      if declared && declared != ats.timestamp.hash_algorithm_oid
        raise MalformedRecordError.new(
          "#{at(ci, ai)}: digestAlgorithm differs from the hash algorithm of the time-stamp", **where
        )
      end

      algorithm = ats.digest_algorithm # raises UnsupportedAlgorithmError
      values = ats.reduced_hashtree&.partial_hashtrees&.flatten || []
      return if values.all? { _1.bytesize == algorithm.digest_size }

      raise MalformedRecordError.new("#{at(ci, ai)}: a hash in reducedHashtree is not a #{algorithm} hash", **where)
    end

    # Steps 2 and 3.
    def verify_chain!(chain, ci)
      algorithm = chain.archive_timestamps[0].digest_algorithm
      chain.archive_timestamps.each_with_index do |ats, ai|
        if ai.zero?
          check_covered!(ats, algorithm, data_hash_candidates(algorithm, ci), "the data", ci, ai)
        else
          previous = chain.archive_timestamps[ai - 1].timestamp.to_der
          check_covered!(ats, algorithm, [[algorithm.digest(previous)]], "the previous time-stamp", ci, ai)
        end
      end
    end

    # The hashes that the first partial hash tree of chain ci must contain,
    # as alternatives. In the first chain they are the hashes of the data
    # (each member of a data group). In later chains they are H(H(d) + ha),
    # where ha is the hash of the older chains; both the fixed order and the
    # sorted order of the concatenation are accepted (docs/design.md 3.5).
    def data_hash_candidates(algorithm, ci)
      hashes = @data.member_digests(algorithm)
      return [hashes] if ci.zero?

      ha = algorithm.digest(@record.archive_timestamp_sequence_der(ci))
      [hashes.map { algorithm.digest(_1, ha) }, hashes.map { algorithm.digest(*[_1, ha].sort) }].uniq
    end

    def check_covered!(ats, algorithm, candidates, subject, ci, ai)
      imprint = ats.timestamp.message_imprint
      contained = false
      candidates.each do |hashes|
        # Without a reduced hash tree, the hashes themselves make the root.
        tree = ats.reduced_hashtree || ReducedHashtree.new([hashes])
        next unless hashes.all? { |h| tree.leaf_values.include?(Digest.new(h)) }
        return if tree.root(algorithm) == imprint

        contained = true
      end

      where = { chain_index: ci, ats_index: ai }
      if contained
        raise HashMismatchError.new("#{at(ci, ai)}: the root of the hash tree does not match the time-stamp", **where)
      end

      raise HashMismatchError.new("#{at(ci, ai)}: #{subject} is not covered by the reduced hash tree", **where)
    end

    # Step 4.
    def check_times!(time)
      previous = nil
      entries.each do |ats, ci, ai|
        gen_time = ats.timestamp.gen_time
        if previous && gen_time < previous
          raise MalformedRecordError.new("#{at(ci, ai)}: the time-stamp is older than the one before",
                                         chain_index: ci, ats_index: ai)
        end

        previous = gen_time
      end
      return if previous <= time

      _, ci, ai = entries.last
      raise TimestampInvalidError.new("#{at(ci, ai)}: the time-stamp is later than the verification time",
                                      chain_index: ci, ats_index: ai)
    end

    # Step 5. Each time-stamp must have been valid when the next one, which
    # covers it, was made; the last one must be valid at the verification
    # time.
    def validate_timestamps!(validator, time)
      list = entries
      list.each_with_index do |(ats, ci, ai), k|
        reference = k + 1 < list.size ? list[k + 1][0].timestamp.gen_time : time
        valid = begin
          validator.call(ats.timestamp, at: reference)
        rescue TimestampInvalidError => e
          raise TimestampInvalidError.new("#{at(ci, ai)}: #{e.message}", chain_index: ci, ats_index: ai)
        end
        next if valid

        raise TimestampInvalidError.new("#{at(ci, ai)}: rejected by the time-stamp validator",
                                        chain_index: ci, ats_index: ai)
      end
    end

    def at(ci, ai)
      "chain #{ci}, ArchiveTimeStamp #{ai}"
    end
  end
end
