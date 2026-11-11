# frozen_string_literal: true

module EvidenceRecord
  # A reduced hash tree (RFC 4998 §4.1): the sequence of partial hash trees
  # needed to recompute the root from one leaf. The first partial hash tree
  # holds the leaf itself (for a data object group, the hashes of all its
  # members) and possibly its siblings; each following one holds the siblings
  # at the next level.
  #
  # The root is computed with the generic RFC algorithm, so trees of any shape
  # (binary or n-ary) are supported (docs/design.md 4.1, 5.2).
  class ReducedHashtree
    attr_reader :partial_hashtrees

    class << self
      # The hash of one node from the values that are hashed together:
      # a single value is used as it is, several values are sorted in binary
      # ascending order, concatenated and hashed.
      def node_hash(algorithm, values)
        return values[0] if values.size == 1

        algorithm.digest(*values.sort)
      end
    end

    # partial_hashtrees: an Array of non-empty Arrays of Digests (or binary
    # Strings).
    def initialize(partial_hashtrees)
      unless partial_hashtrees.is_a?(Array) && !partial_hashtrees.empty?
        raise ArgumentError, "partial_hashtrees must be a non-empty Array"
      end

      @partial_hashtrees = partial_hashtrees.each_with_index.map do |values, i|
        unless values.is_a?(Array) && !values.empty?
          raise ArgumentError, "partial hash tree #{i} must be a non-empty Array"
        end

        values.map { Digest.wrap(_1, "partial hash tree #{i} value") }.freeze
      end.freeze
      freeze
    end

    # The first partial hash tree: the leaf, or the members of a data object
    # group, possibly with siblings.
    def leaf_values
      @partial_hashtrees[0]
    end

    # The root hash recomputed with algorithm (a Symbol or DigestAlgorithm).
    #
    # The lengths of the values are not checked here; the verifier does that.
    def root(algorithm)
      algorithm = DigestAlgorithm.fetch(algorithm)
      first, *rest = @partial_hashtrees.map { |values| values.map(&:to_binary) }
      current = self.class.node_hash(algorithm, first)
      rest.each { |values| current = algorithm.digest(*([current] + values).sort) }
      Digest.new(current)
    end

    def ==(other)
      other.is_a?(ReducedHashtree) && @partial_hashtrees == other.partial_hashtrees
    end
    alias eql? ==

    def hash
      [ReducedHashtree, @partial_hashtrees].hash
    end

    def inspect
      "#<#{self.class.name} #{@partial_hashtrees.map { |v| v.map { _1.to_hex[0, 8] } }.inspect}>"
    end
  end
end
