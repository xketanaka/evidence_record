# frozen_string_literal: true

module EvidenceRecord
  # An Evidence Record (RFC 4998 §3): the RFC's EvidenceRecord type.
  #
  #   EvidenceRecord ::= SEQUENCE {
  #     version                   INTEGER { v1(1) },
  #     digestAlgorithms          SEQUENCE OF AlgorithmIdentifier,
  #     cryptoInfos               [0] CryptoInfos OPTIONAL,
  #     encryptionInfo            [1] EncryptionInfo OPTIONAL,
  #     archiveTimeStampSequence  ArchiveTimeStampSequence }
  #
  # Only DER is accepted, and the original DER is kept and returned by
  # #to_der (docs/design.md 7.1).
  class Record
    VERSION = 1

    attr_reader :version, :digest_algorithm_oids, :chains
    # The cryptoInfos and encryptionInfo fields as they were read (DER,
    # including their [0] / [1] tags), or nil. They are kept but not
    # interpreted (docs/design.md 7.3).
    attr_reader :crypto_infos, :encryption_info

    class << self
      # Parses a DER-encoded Evidence Record. Raises ParseError when der is not
      # DER or does not match the structure of RFC 4998.
      def from_der(der)
        new(DER.parse(der, "EvidenceRecord"))
      end

      # Internal: encodes a new Evidence Record from Chains. digestAlgorithms
      # lists the algorithms of the ArchiveTimeStamps in order of appearance.
      def build(chains)
        from_der(encode(digest_algorithm_ders([], chains), nil, nil, chains))
      end

      # Internal.
      def encode(digest_algorithm_ders, crypto_infos, encryption_info, chains)
        DER.sequence([DER.encode_integer(VERSION), DER.sequence(digest_algorithm_ders),
                      crypto_infos, encryption_info, DER.sequence(chains.map(&:to_der))].compact)
      end

      # Internal: existing (OID, DER) pairs plus AlgorithmIdentifiers for the
      # algorithms of chains that are not among them.
      def digest_algorithm_ders(existing, chains)
        oids = existing.map(&:first)
        added = chains.flat_map(&:archive_timestamps).map(&:digest_algorithm_oid).uniq - oids
        existing.map(&:last) + added.map { AlgorithmIdentifier.encode(DigestAlgorithm.from_oid(_1)) }
      end

      private :new
    end

    def initialize(node)
      what = "EvidenceRecord"
      @der = node.raw
      version, algorithms, *optional, sequence = DER.children_of(node, what, size: 3..5)
      @version = DER.integer(version, "#{what} version")
      raise ParseError, "#{what}: unsupported version #{@version}" unless @version == VERSION

      @digest_algorithms = DER.children_of(algorithms, "#{what} digestAlgorithms").map do |alg|
        [AlgorithmIdentifier.parse(alg, "#{what} digestAlgorithms"), alg.raw]
      end.freeze
      @digest_algorithm_oids = @digest_algorithms.map(&:first).freeze
      parse_optional(optional, what)
      @chains = DER.children_of(sequence, "#{what} archiveTimeStampSequence").each_with_index.map do |chain, i|
        Chain.from_node(chain, "archiveTimeStampSequence[#{i}]")
      end.freeze
      freeze
    end

    # The digestAlgorithms field as DigestAlgorithms. Raises
    # UnsupportedAlgorithmError if it lists other algorithms (see
    # #digest_algorithm_oids).
    def digest_algorithms
      @digest_algorithm_oids.map { DigestAlgorithm.from_oid(_1) }
    end

    # The time the data is proven to have existed: the genTime of the first
    # ArchiveTimeStamp. nil if the record has no ArchiveTimeStamp.
    #
    # This is only meaningful after the record has been verified.
    def proven_time
      @chains.first&.archive_timestamps&.first&.timestamp&.gen_time
    end

    # Whether other was built from the same hash tree: the first time-stamps
    # are the same. Such records can share the TSA response of a time-stamp
    # renewal.
    def related_to?(other)
      raise ArgumentError, "other must be an EvidenceRecord::Record, got #{other.class}" unless other.is_a?(Record)

      mine = @chains.first&.archive_timestamps&.first
      theirs = other.chains.first&.archive_timestamps&.first
      !mine.nil? && !theirs.nil? && mine.timestamp == theirs.timestamp
    end

    # Verifies that this record proves the existence of data (docs/design.md
    # 3.6, 5.1): the hash chain from data to every time-stamp, the order of
    # the time-stamps, and the validity of each time-stamp, checked with
    # timestamp_validator (see TimestampValidator).
    #
    # data is a String, a PrehashedData or a DataGroup. at is the time of
    # verification; the last time-stamp must be valid at that time.
    #
    # Returns true or false. Invalid arguments raise ArgumentError, and
    # unsupported hash algorithms raise UnsupportedAlgorithmError.
    def verify(data:, timestamp_validator:, at: Time.now)
      verify!(data: data, timestamp_validator: timestamp_validator, at: at)
    rescue VerificationError
      false
    end

    # Like #verify, but raises a VerificationError telling why and where the
    # verification failed.
    def verify!(data:, timestamp_validator:, at: Time.now)
      unless timestamp_validator.respond_to?(:call)
        raise ArgumentError, "timestamp_validator must respond to call(token, at:)"
      end
      raise ArgumentError, "at must be a Time, got #{at.class}" unless at.is_a?(Time)

      Verifier.new(self, data).verify!(timestamp_validator: timestamp_validator, at: at)
    end

    # Verifies only the structure and the hash chain from data to every
    # time-stamp. Neither the signatures nor the times of the time-stamps are
    # checked, so this alone does not prove anything about time.
    def verify_hashes(data:)
      verify_hashes!(data: data)
    rescue VerificationError
      false
    end

    # Like #verify_hashes, but raises a VerificationError.
    def verify_hashes!(data:)
      Verifier.new(self, data).verify_hashes!
    end

    # A time-stamp renewal of this record (TimestampRenewal): a new time-stamp
    # covering the time-stamps of the last chain. Raises MalformedRecordError
    # when the record has no ArchiveTimeStamp, and UnsupportedAlgorithmError
    # when the last chain uses an unsupported hash algorithm.
    def timestamp_renewal
      TimestampRenewal.new(self)
    end

    # A hash-tree renewal of this record (HashTreeRenewal): a new chain with
    # the hash algorithm digest_algorithm (:sha256, :sha384 or :sha512),
    # covering data and the older chains.
    #
    # data is a String, a PrehashedData or a DataGroup, as for #verify; a
    # PrehashedData needs hashes for the algorithms of the record and for
    # digest_algorithm. The record is first checked against data with
    # #verify_hashes!, which raises a VerificationError when they do not
    # match.
    def hash_tree_renewal(data:, digest_algorithm:)
      HashTreeRenewal.new(self, data: data, digest_algorithm: digest_algorithm)
    end

    def to_der
      @der
    end

    def ==(other)
      other.is_a?(Record) && to_der == other.to_der
    end
    alias eql? ==

    def hash
      [Record, @der].hash
    end

    def inspect
      "#<#{self.class.name} digest_algorithm_oids=#{@digest_algorithm_oids} chains=#{@chains.inspect}>"
    end

    # Internal: the DER of an ArchiveTimeStampSequence holding the first count
    # chains, whose hash (ha) is used by a hash-tree renewal (RFC 4998 §5.2).
    def archive_timestamp_sequence_der(count = @chains.size)
      DER.sequence(@chains.first(count).map(&:to_der))
    end

    # Internal: a new Record with chains replaced, keeping the other fields as
    # they are and adding the algorithms of new chains to digestAlgorithms.
    def with_chains(chains)
      algorithms = self.class.digest_algorithm_ders(@digest_algorithms, chains)
      self.class.from_der(self.class.encode(algorithms, @crypto_infos, @encryption_info, chains))
    end

    private

    def parse_optional(nodes, what)
      tags = nodes.map { |n| n.tag_class == :context && n.constructed? ? n.tag : nil }
      raise ParseError, "#{what}: unexpected elements" unless [[], [0], [1], [0, 1]].include?(tags)

      nodes.each do |node|
        if node.tag.zero?
          # CryptoInfos ::= SEQUENCE SIZE (1..MAX) OF Attribute
          unless !node.children.empty? && node.children.all? { _1.universal?(DER::SEQUENCE) }
            raise ParseError, "#{what}: invalid cryptoInfos"
          end

          @crypto_infos = node.raw
        else
          # EncryptionInfo ::= SEQUENCE { encryptionInfoType OBJECT IDENTIFIER,
          #   encryptionInfoValue ANY DEFINED BY encryptionInfoType }
          type, = DER.children_of(node, "#{what} encryptionInfo", size: 2, context: 1)
          DER.oid(type, "#{what} encryptionInfo")
          @encryption_info = node.raw
        end
      end
    end
  end
end
