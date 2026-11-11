# frozen_string_literal: true

require "pathname"

module EvidenceRecord
  # Hash values of a data object computed elsewhere, given per algorithm
  # (docs/design.md 3.7.1).
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

    # The hash for algorithm (a Symbol or DigestAlgorithm) as a Digest.
    def [](algorithm)
      bytes = @hashes[DigestAlgorithm.fetch(algorithm)]
      bytes && Digest.new(bytes)
    end

    def inspect
      "#<#{self.class.name} #{@hashes.map { |a, b| "#{a}=#{b.unpack1('H*')}" }.join(' ')}>"
    end
  end

  # A data object group: several data objects covered by one Evidence Record
  # (RFC 4998 §4.2). Members are Strings, IOs, Pathnames or PrehashedData;
  # groups cannot be nested.
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

  # Internal: turns the values accepted as data (String, IO, Pathname,
  # PrehashedData, DataGroup) into objects that compute hash values, caching
  # them per algorithm.
  module DataSource
    CHUNK_SIZE = 64 * 1024

    module_function

    def check!(value, name = "data")
      return if value.is_a?(String) || value.is_a?(Pathname) || value.is_a?(PrehashedData) ||
                value.respond_to?(:read)

      raise ArgumentError,
            "#{name} must be a String, an IO, a Pathname, an EvidenceRecord::PrehashedData " \
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
        @io_start = value.respond_to?(:pos) ? safe_pos(value) : nil if io?
        @io_consumed = false
      end

      def group?
        false
      end

      # The hash of the data object, as a BINARY String.
      def digest(algorithm)
        algorithm = DigestAlgorithm.fetch(algorithm)
        prefetch([algorithm]) unless @cache.key?(algorithm)
        @cache.fetch(algorithm)
      end

      # [hash]; the list that becomes the first partial hash tree.
      def member_digests(algorithm)
        [digest(algorithm)]
      end

      # Computes the hashes for several algorithms, reading the data only once.
      def prefetch(algorithms)
        missing = algorithms.map { DigestAlgorithm.fetch(_1) }.uniq.reject { @cache.key?(_1) }
        return if missing.empty?

        case @value
        when PrehashedData then prehashed(missing)
        when String then missing.each { |a| @cache[a] = a.digest(@value).freeze }
        when Pathname then File.open(@value, "rb") { |f| stream(f, missing) }
        else read_io(missing)
        end
      end

      private

      def io?
        !(@value.is_a?(String) || @value.is_a?(Pathname) || @value.is_a?(PrehashedData))
      end

      def safe_pos(io)
        io.pos
      rescue StandardError
        nil
      end

      def prehashed(missing)
        missing.each do |a|
          d = @value[a] or raise ArgumentError, "PrehashedData has no #{a} hash, which is required here"
          @cache[a] = d.to_binary
        end
      end

      def read_io(missing)
        if @io_consumed
          unless @io_start && @value.respond_to?(:seek)
            raise ArgumentError,
                  "the IO has already been read and cannot be rewound to hash it with #{missing.join(', ')}"
          end

          @value.seek(@io_start)
        end
        @io_consumed = true
        stream(@value, missing)
      end

      def stream(io, missing)
        digests = missing.map(&:new_openssl_digest)
        while (chunk = io.read(CHUNK_SIZE))
          digests.each { _1.update(chunk) }
        end
        missing.zip(digests) { |a, d| @cache[a] = d.digest.freeze }
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

      def prefetch(algorithms)
        @members.each { _1.prefetch(algorithms) }
      end

      def member_digests(algorithm)
        @members.map { _1.digest(algorithm) }
      end
    end
  end
end
