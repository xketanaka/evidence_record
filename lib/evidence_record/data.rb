# frozen_string_literal: true

module EvidenceRecord
  # Hash values of a data object computed elsewhere, given per algorithm
  # (docs/design.md 3.7.1). Use it for data that is not at hand or too large
  # to read into a String.
  #
  #   EvidenceRecord::PrehashedData.new(sha256: d256, sha512: d512)
  #
  # The library cannot check that the hashes were computed from the same data.
  class PrehashedData
    def initialize(**hashes)
      raise ArgumentError, "at least one hash must be given" if hashes.empty?

      @hashes = hashes.to_h do |name, value|
        algorithm = DigestAlgorithm.fetch(name)
        bytes = Digest.bytes_of(value, "#{name} hash")
        unless bytes.bytesize == algorithm.digest_size
          raise ArgumentError,
                "#{name} hash must be #{algorithm.digest_size} bytes, got #{bytes.bytesize}"
        end
        [algorithm, bytes]
      end.freeze
      freeze
    end

    def algorithms
      @hashes.keys
    end

    # The hash for algorithm (a Symbol or DigestAlgorithm) as a Digest, or nil.
    def [](algorithm)
      bytes = @hashes[DigestAlgorithm.fetch(algorithm)]
      bytes && Digest.new(bytes)
    end

    def inspect
      "#<#{self.class.name} #{@hashes.map { |a, b| "#{a}=#{b.unpack1('H*')}" }.join(' ')}>"
    end
  end

  # A data object group: several data objects covered by one Evidence Record
  # (RFC 4998 §4.2). Members are Strings or PrehashedData; groups cannot be
  # nested.
  class DataGroup
    attr_reader :members

    def initialize(members)
      raise ArgumentError, "members must be an Array, got #{members.class}" unless members.is_a?(Array)
      raise ArgumentError, "a data group needs at least one member" if members.empty?

      members.each_with_index do |m, i|
        raise ArgumentError, "data groups cannot be nested (member #{i})" if m.is_a?(DataGroup)

        DataSource.check!(m, "member #{i}")
      end
      @members = members.dup.freeze
      freeze
    end

    def size
      @members.size
    end
  end

  # Internal: turns the values accepted as data (String, PrehashedData,
  # DataGroup) into objects that compute hash values, caching them per
  # algorithm.
  module DataSource
    module_function

    def check!(value, name = "data")
      return if value.is_a?(String) || value.is_a?(PrehashedData)

      raise ArgumentError,
            "#{name} must be a String, an EvidenceRecord::PrehashedData " \
            "or an EvidenceRecord::DataGroup, got #{value.class}"
    end

    def wrap(value)
      case value
      when Single, Group then value
      when DataGroup then Group.new(value.members.map { Single.new(_1) })
      else
        check!(value)
        Single.new(value)
      end
    end

    # One data object.
    class Single
      def initialize(value)
        @value = value
        @cache = {}
      end

      def group?
        false
      end

      # The hash of the data object, as a BINARY String.
      def digest(algorithm)
        algorithm = DigestAlgorithm.fetch(algorithm)
        @cache[algorithm] ||= compute(algorithm)
      end

      # [hash]; the list that becomes the first partial hash tree.
      def member_digests(algorithm)
        [digest(algorithm)]
      end

      private

      def compute(algorithm)
        case @value
        when PrehashedData
          d = @value[algorithm] or
            raise ArgumentError, "PrehashedData has no #{algorithm} hash, which is required here"
          d.to_binary
        else
          algorithm.digest(@value).freeze
        end
      end
    end

    # A data object group.
    class Group
      attr_reader :members

      def initialize(members)
        @members = members
      end

      def group?
        true
      end

      def member_digests(algorithm)
        @members.map { _1.digest(algorithm) }
      end
    end
  end
end
