# frozen_string_literal: true

module EvidenceRecord
  # An RFC 3161 time-stamp token: the timeStamp field of an ArchiveTimeStamp.
  #
  # The fields of TSTInfo are read with this library's DER reader, not with
  # OpenSSL::Timestamp, because Ruby's OpenSSL cannot parse tokens that carry
  # OCSP responses in the CMS crls field (docs/design.md 7.2). The token's
  # signature is not checked here; that is the job of a timestamp validator.
  #
  # The original DER is kept and returned by #to_der.
  class TimeStampToken
    ID_SIGNED_DATA = "1.2.840.113549.1.7.2"
    ID_CT_TST_INFO = "1.2.840.113549.1.9.16.1.4"

    attr_reader :gen_time, :message_imprint, :hash_algorithm_oid, :serial_number, :policy_id, :nonce

    class << self
      def from_der(der)
        from_node(DER.parse(der, "time-stamp token"), "time-stamp token")
      end

      # Internal: from an already parsed element.
      def from_node(node, what)
        new(node, what)
      end

      private :new
    end

    def initialize(node, what)
      @der = node.raw
      content_type, wrapper = DER.children_of(node, "#{what} (ContentInfo)", size: 2)
      unless DER.oid(content_type, what) == ID_SIGNED_DATA
        raise ParseError, "#{what}: only RFC 3161 time-stamp tokens (CMS SignedData) are supported"
      end

      signed_data = DER.children_of(wrapper, what, size: 1, context: 0)[0]
      @certificate_ders = parse_signed_data(signed_data, "#{what} (SignedData)")
      freeze
    end

    # The hash algorithm of the message imprint, as a DigestAlgorithm.
    # Raises UnsupportedAlgorithmError for other algorithms (see
    # #hash_algorithm_oid).
    def hash_algorithm
      DigestAlgorithm.from_oid(@hash_algorithm_oid)
    end

    # The certificates included in the token (normally the TSA certificate and
    # possibly its chain), as OpenSSL::X509::Certificate.
    def certificates
      @certificate_ders.map { OpenSSL::X509::Certificate.new(_1) }
    end

    def to_der
      @der
    end

    def ==(other)
      other.is_a?(TimeStampToken) && to_der == other.to_der
    end
    alias eql? ==

    def hash
      [TimeStampToken, @der].hash
    end

    def inspect
      "#<#{self.class.name} gen_time=#{@gen_time.getutc.strftime("%Y-%m-%dT%H:%M:%S.%LZ")} " \
        "message_imprint=#{@message_imprint.to_hex} serial_number=#{@serial_number}>"
    end

    private

    # SignedData ::= SEQUENCE { version, digestAlgorithms SET, encapContentInfo,
    #   certificates [0] IMPLICIT OPTIONAL, crls [1] IMPLICIT OPTIONAL,
    #   signerInfos SET }
    def parse_signed_data(node, what)
      children = DER.children_of(node, what, size: 4..6)
      DER.integer(children[0], "#{what} version")
      DER.expect(children[1], "#{what} digestAlgorithms", DER::SET)
      DER.expect(children[-1], "#{what} signerInfos", DER::SET)
      optional = children[3...-1]
      tags = optional.map { |n| n.tag_class == :context && n.constructed? ? n.tag : nil }
      unless [[], [0], [1], [0, 1]].include?(tags)
        raise ParseError, "#{what}: unexpected elements before signerInfos"
      end

      parse_encap_content_info(children[2], "#{what} encapContentInfo")
      certificates = optional.find { _1.tag.zero? }
      (certificates&.children || []).select { _1.universal?(DER::SEQUENCE) }.map(&:raw)
    end

    def parse_encap_content_info(node, what)
      content_type, wrapper = DER.children_of(node, what, size: 2)
      unless DER.oid(content_type, what) == ID_CT_TST_INFO
        raise ParseError, "#{what}: the content is not a TSTInfo"
      end

      econtent = DER.octet_string(DER.children_of(wrapper, what, size: 1, context: 0)[0], what)
      parse_tst_info(DER.parse(econtent, "TSTInfo"), "TSTInfo")
    end

    # TSTInfo ::= SEQUENCE { version INTEGER { v1(1) }, policy, messageImprint,
    #   serialNumber, genTime, accuracy OPTIONAL, ordering BOOLEAN DEFAULT FALSE,
    #   nonce INTEGER OPTIONAL, tsa [0] OPTIONAL, extensions [1] OPTIONAL }
    def parse_tst_info(node, what)
      version, policy, imprint, serial, gen_time, *rest = DER.children_of(node, what, size: 5..10)
      raise ParseError, "#{what}: unsupported version" unless DER.integer(version, "#{what} version") == 1

      @policy_id = DER.oid(policy, "#{what} policy")
      parse_message_imprint(imprint, "#{what} messageImprint")
      @serial_number = DER.integer(serial, "#{what} serialNumber")
      @gen_time = DER.generalized_time(gen_time, "#{what} genTime")
      @nonce = rest.find { _1.universal?(DER::INTEGER) }&.then { DER.integer(_1, "#{what} nonce") }
    end

    def parse_message_imprint(node, what)
      algorithm, hashed = DER.children_of(node, what, size: 2)
      @hash_algorithm_oid = AlgorithmIdentifier.parse(algorithm, "#{what} hashAlgorithm")
      @message_imprint = Digest.new(DER.octet_string(hashed, "#{what} hashedMessage"))
      known = DigestAlgorithm::BY_OID[@hash_algorithm_oid]
      return if known.nil? || known.digest_size == @message_imprint.bytesize

      raise ParseError, "#{what}: the #{known} hash must be #{known.digest_size} bytes"
    end
  end
end
