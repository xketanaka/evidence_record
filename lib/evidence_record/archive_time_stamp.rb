# frozen_string_literal: true

module EvidenceRecord
  # An ArchiveTimeStamp (RFC 4998 §4.1): a time-stamp token and the reduced
  # hash tree leading from a data object (or an earlier time-stamp) to the
  # time-stamped root.
  #
  #   ArchiveTimeStamp ::= SEQUENCE {
  #     digestAlgorithm [0] AlgorithmIdentifier OPTIONAL,
  #     attributes      [1] Attributes OPTIONAL,
  #     reducedHashtree [2] SEQUENCE OF PartialHashtree OPTIONAL,
  #     timeStamp       ContentInfo }
  #
  # The original DER is kept and returned by #to_der.
  class ArchiveTimeStamp
    # The time-stamp token (TimeStampToken).
    attr_reader :timestamp
    # The ReducedHashtree, or nil when the field is absent (the time-stamp
    # covers the hash of a single data object directly).
    attr_reader :reduced_hashtree
    # The attributes field as it was read (DER, including its [1] tag), or
    # nil. It is kept but not interpreted (docs/design.md 7.3).
    attr_reader :attributes
    # Internal: the OID of the digestAlgorithm field, or nil when absent.
    attr_reader :declared_digest_algorithm_oid

    class << self
      def from_der(der)
        from_node(DER.parse(der, "ArchiveTimeStamp"), "ArchiveTimeStamp")
      end

      # Internal: from an already parsed element.
      def from_node(node, what)
        new(node, what)
      end

      # Internal: encodes a new ArchiveTimeStamp. Used by the generator and
      # the renewals.
      def build(timestamp:, reduced_hashtree: nil, digest_algorithm: nil)
        parts = []
        parts << DER.context(0, AlgorithmIdentifier.encode_content(digest_algorithm)) if digest_algorithm
        if reduced_hashtree
          partials = reduced_hashtree.partial_hashtrees.map do |values|
            DER.sequence(values.map { DER.encode_octet_string(_1.to_binary) })
          end
          parts << DER.context(2, partials.join)
        end
        parts << timestamp.to_der
        from_der(DER.sequence(parts))
      end

      private :new
    end

    def initialize(node, what)
      @der = node.raw
      *fields, timestamp = DER.children_of(node, what, size: 1..4)
      @timestamp = TimeStampToken.from_node(timestamp, "#{what} timeStamp")

      previous_tag = -1
      fields.each do |field|
        tag = field.tag_class == :context && field.constructed? ? field.tag : nil
        unless tag && tag <= 2 && tag > previous_tag
          raise ParseError, "#{what}: unexpected element before timeStamp"
        end

        previous_tag = tag
        case tag
        when 0 then @declared_digest_algorithm_oid = AlgorithmIdentifier.parse(field, "#{what} digestAlgorithm", context: 0)
        when 1 then @attributes = parse_attributes(field, "#{what} attributes")
        when 2 then @reduced_hashtree = parse_reduced_hashtree(field, "#{what} reducedHashtree")
        end
      end
      freeze
    end

    # The OID of the hash algorithm of the reduced hash tree: the
    # digestAlgorithm field, or the hash algorithm of the time-stamp when the
    # field is absent (RFC 4998 §4.1).
    def digest_algorithm_oid
      @declared_digest_algorithm_oid || @timestamp.hash_algorithm_oid
    end

    # The hash algorithm of the reduced hash tree, as a DigestAlgorithm.
    # Raises UnsupportedAlgorithmError for other algorithms.
    def digest_algorithm
      DigestAlgorithm.from_oid(digest_algorithm_oid)
    end

    def to_der
      @der
    end

    def ==(other)
      other.is_a?(ArchiveTimeStamp) && to_der == other.to_der
    end
    alias eql? ==

    def hash
      [ArchiveTimeStamp, @der].hash
    end

    def inspect
      shape = @reduced_hashtree ? @reduced_hashtree.partial_hashtrees.map(&:size).join("-") : "none"
      "#<#{self.class.name} digest_algorithm_oid=#{digest_algorithm_oid} " \
        "reduced_hashtree=#{shape} timestamp=#{@timestamp.inspect}>"
    end

    private

    # Attributes ::= SET SIZE (1..MAX) OF Attribute
    def parse_attributes(node, what)
      if node.children.empty? || !node.children.all? { _1.universal?(DER::SEQUENCE) } ||
         !DER.sorted?(node.children)
        raise ParseError, "#{what}: invalid Attributes"
      end

      node.raw
    end

    # SEQUENCE OF PartialHashtree; PartialHashtree ::= SEQUENCE OF OCTET STRING
    def parse_reduced_hashtree(node, what)
      partials = node.children.each_with_index.map do |partial, i|
        DER.children_of(partial, "#{what}[#{i}]").map { DER.octet_string(_1, "#{what}[#{i}]") }
      end
      ReducedHashtree.new(partials)
    rescue ArgumentError => e
      raise ParseError, "#{what}: #{e.message}"
    end
  end
end
