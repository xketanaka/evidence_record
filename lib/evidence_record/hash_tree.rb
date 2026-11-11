# frozen_string_literal: true

module EvidenceRecord
  # A hash tree built from leaves, used to generate reduced hash trees
  # (RFC 4998 §4.2). It only computes hashes; it knows nothing about ASN.1
  # or time-stamps.
  #
  # Each leaf is the list of hashes of one data object (one hash) or of one
  # data object group (the hashes of all its members). The tree is binary and
  # built like Bouncy Castle's BinaryTreeRootCalculator (docs/design.md 4.2):
  # the leaves are sorted by their hash, adjacent pairs are hashed together,
  # and the last node of an odd-sized level is carried up unchanged.
  class HashTree
    attr_reader :digest_algorithm

    def initialize(digest_algorithm: :sha256)
      @digest_algorithm = DigestAlgorithm.fetch(digest_algorithm)
      @leaves = []
      @levels = nil
    end

    # Adds a leaf from the hashes of a data object ([hash]) or of the members
    # of a data object group, and returns the index of the new leaf (in the
    # order of addition).
    def add(member_hashes)
      unless member_hashes.is_a?(Array) && !member_hashes.empty?
        raise ArgumentError, "member_hashes must be a non-empty Array"
      end

      values = member_hashes.map do |h|
        bytes = Digest.bytes_of(h)
        unless bytes.bytesize == @digest_algorithm.digest_size
          raise ArgumentError,
                "hash must be #{@digest_algorithm.digest_size} bytes for #{@digest_algorithm}, got #{bytes.bytesize}"
        end
        bytes
      end.freeze
      @leaves << values
      @levels = nil
      @leaves.size - 1
    end

    def size
      @leaves.size
    end

    def empty?
      @leaves.empty?
    end

    # The hash of the leaf at index (for a group, the hash of its members).
    def leaf_hash(index)
      check_index!(index)
      Digest.new(node_hash(@leaves[index]))
    end

    def root
      raise Error, "an empty hash tree has no root" if empty?

      Digest.new(levels.last[0])
    end

    # The reduced hash tree for the leaf at index (in the order of addition).
    def reduced_hashtree(index)
      check_index!(index)
      all_levels = levels # also computes @positions
      partials = [@leaves[index]]
      pos = @positions[index]
      all_levels[0...-1].each do |level|
        sibling = pos ^ 1
        partials << [level[sibling]] if sibling < level.size
        pos >>= 1
      end
      ReducedHashtree.new(partials)
    end

    def inspect
      "#<#{self.class.name} #{@digest_algorithm} size=#{size}>"
    end

    private

    def node_hash(values)
      ReducedHashtree.node_hash(@digest_algorithm, values)
    end

    # levels[0] holds the leaf hashes sorted in binary ascending order;
    # levels.last holds the root.
    def levels
      return @levels if @levels

      sorted = @leaves.each_with_index.map { |values, i| [node_hash(values), i] }.sort
      @positions = Array.new(@leaves.size)
      sorted.each_with_index { |(_, i), pos| @positions[i] = pos }

      level = sorted.map(&:first)
      levels = [level]
      while level.size > 1
        level = level.each_slice(2).map { |pair| pair.size == 2 ? @digest_algorithm.digest(*pair.sort) : pair[0] }
        levels << level
      end
      @levels = levels
    end

    def check_index!(index)
      raise ArgumentError, "index must be an Integer, got #{index.class}" unless index.is_a?(Integer)
      raise IndexError, "index #{index} out of range (size #{size})" unless index >= 0 && index < size
    end
  end
end
