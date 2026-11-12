# frozen_string_literal: true

module EvidenceRecord
  # Internal: reading and writing the AlgorithmIdentifiers of hash
  # algorithms.
  #
  # Any OID is read, so that Evidence Records using other algorithms can still
  # be parsed; DigestAlgorithm.from_oid raises UnsupportedAlgorithmError when
  # such an algorithm is used. Parameters of SHA-2 must be absent or NULL
  # (RFC 5754 §2); absent is generated.
  module AlgorithmIdentifier
    module_function

    # node: a SEQUENCE, or a constructed element with an implicit tag.
    # Returns the OID as a dotted String.
    def parse(node, what)
      unless node&.constructed? && (1..2).cover?(node.children.size)
        raise ParseError, "#{what}: invalid AlgorithmIdentifier"
      end

      oid = DER.oid(node.children[0], what)
      params = node.children[1]
      if params && DigestAlgorithm::BY_OID.key?(oid) && !params.universal?(DER::NULL)
        raise ParseError, "#{what}: parameters of #{DigestAlgorithm::BY_OID[oid]} must be absent or NULL"
      end

      oid
    end

    # The contents octets of an AlgorithmIdentifier (to be wrapped in a
    # SEQUENCE or an implicit tag).
    def encode_content(algorithm)
      DER.encode_oid(algorithm.oid)
    end

    def encode(algorithm)
      DER.sequence([encode_content(algorithm)])
    end
  end
end
