# frozen_string_literal: true

require "openssl"

module EvidenceRecord
  # A supported hash algorithm. Only SHA-256, SHA-384 and SHA-512 are
  # supported (docs/design.md 4.4).
  #
  # Instances are looked up with DigestAlgorithm.fetch (by Symbol) or
  # DigestAlgorithm.from_oid; they are frozen singletons.
  class DigestAlgorithm
    attr_reader :name, :oid, :digest_size

    def initialize(name, oid, openssl_name, digest_size)
      @name = name
      @oid = oid
      @openssl_name = openssl_name
      @digest_size = digest_size
      freeze
    end

    SHA256 = new(:sha256, "2.16.840.1.101.3.4.2.1", "SHA256", 32)
    SHA384 = new(:sha384, "2.16.840.1.101.3.4.2.2", "SHA384", 48)
    SHA512 = new(:sha512, "2.16.840.1.101.3.4.2.3", "SHA512", 64)

    ALL = [SHA256, SHA384, SHA512].freeze
    BY_NAME = ALL.to_h { [_1.name, _1] }.freeze
    BY_OID = ALL.to_h { [_1.oid, _1] }.freeze

    class << self
      # Accepts a Symbol (:sha256, :sha384, :sha512) or a DigestAlgorithm.
      def fetch(value)
        case value
        when DigestAlgorithm then value
        when Symbol
          BY_NAME.fetch(value) do
            raise UnsupportedAlgorithmError,
                  "unsupported digest algorithm #{value.inspect} (supported: #{BY_NAME.keys.map(&:inspect).join(', ')})"
          end
        else raise ArgumentError, "digest algorithm must be a Symbol, got #{value.class}"
        end
      end

      def from_oid(oid)
        BY_OID.fetch(oid) { raise UnsupportedAlgorithmError, "unsupported digest algorithm OID #{oid}" }
      end
    end

    # The hash of the concatenation of parts, as a BINARY String.
    def digest(*parts)
      d = new_openssl_digest
      parts.each { d.update(_1) }
      d.digest
    end

    def new_openssl_digest
      OpenSSL::Digest.new(@openssl_name)
    end

    def to_s
      @name.to_s
    end

    def inspect
      "#<#{self.class.name} #{@name}>"
    end
  end
end
