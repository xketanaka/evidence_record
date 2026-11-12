# frozen_string_literal: true

module EvidenceRecord
  # An ArchiveTimeStampChain (RFC 4998 §5): ArchiveTimeStamps that use the
  # same hash algorithm, each covering the time-stamp of the one before.
  #
  # The original DER is kept and returned by #to_der.
  class Chain
    attr_reader :archive_timestamps

    class << self
      def from_der(der)
        from_node(DER.parse(der, "ArchiveTimeStampChain"), "ArchiveTimeStampChain")
      end

      # Internal: from an already parsed element.
      def from_node(node, what)
        new(node, what)
      end

      # Internal: encodes a new chain from ArchiveTimeStamps.
      def build(archive_timestamps)
        from_der(DER.sequence(archive_timestamps.map(&:to_der)))
      end

      private :new
    end

    def initialize(node, what)
      @der = node.raw
      @archive_timestamps = DER.children_of(node, what).each_with_index.map do |ats, i|
        ArchiveTimeStamp.from_node(ats, "#{what}[#{i}]")
      end.freeze
      freeze
    end

    def to_der
      @der
    end

    def ==(other)
      other.is_a?(Chain) && to_der == other.to_der
    end
    alias eql? ==

    def hash
      [Chain, @der].hash
    end

    def inspect
      "#<#{self.class.name} #{@archive_timestamps.inspect}>"
    end
  end
end
