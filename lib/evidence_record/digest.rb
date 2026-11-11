# frozen_string_literal: true

module EvidenceRecord
  # An immutable hash value. The bytes are always held as a frozen BINARY
  # String. The same design as CTMerkle::Digest of the ct_merkle gem.
  #
  # A Digest does not know its hash algorithm: in RFC 4998 the algorithm is
  # given by the context (the ArchiveTimeStamp or ArchiveTimeStampChain).
  class Digest
    HEX_PATTERN = /\A(?:[0-9a-fA-F]{2})*\z/

    class << self
      def from_hex(str)
        raise ArgumentError, "hex must be a String, got #{str.class}" unless str.is_a?(String)
        raise ArgumentError, "invalid hex string: #{str.inspect}" unless HEX_PATTERN.match?(str)

        new([str].pack("H*"))
      end

      def from_base64(str)
        raise ArgumentError, "base64 must be a String, got #{str.class}" unless str.is_a?(String)

        bytes = begin
          str.unpack1("m0")
        rescue ArgumentError
          raise ArgumentError, "invalid base64 string: #{str.inspect}"
        end
        new(bytes)
      end

      # Returns the bytes of a Digest or a String as a frozen BINARY String.
      # Used internally to accept both kinds of arguments.
      def bytes_of(value, name = "hash")
        case value
        when Digest then value.to_binary
        when String then value.b.freeze
        else raise ArgumentError, "#{name} must be an EvidenceRecord::Digest or a binary String, got #{value.class}"
        end
      end

      # Wraps a Digest or a binary String as a Digest.
      def wrap(value, name = "hash")
        value.is_a?(Digest) ? value : new(bytes_of(value, name))
      end
    end

    def initialize(bytes)
      raise ArgumentError, "bytes must be a String, got #{bytes.class}" unless bytes.is_a?(String)

      @bytes = bytes.b.freeze
      freeze
    end

    def to_binary
      @bytes
    end

    def to_hex
      @bytes.unpack1("H*")
    end

    def to_base64
      [@bytes].pack("m0")
    end

    alias to_s to_hex

    def inspect
      "#<#{self.class.name} #{to_hex}>"
    end

    def bytesize
      @bytes.bytesize
    end

    # Compares bytes with another Digest or a String (encoding is ignored).
    def ==(other)
      case other
      when Digest then @bytes == other.to_binary
      when String then @bytes == other.b
      else false
      end
    end

    # Only Digests are eql?, so that #hash stays consistent.
    def eql?(other)
      other.is_a?(Digest) && @bytes.eql?(other.to_binary)
    end

    def hash
      [Digest, @bytes].hash
    end
  end
end
