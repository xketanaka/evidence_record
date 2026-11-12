# frozen_string_literal: true

module EvidenceRecord
  # Builds Evidence Records for many data objects with one time-stamp
  # (docs/design.md 3.3).
  #
  #   gen = EvidenceRecord::Generator.new(digest_algorithm: :sha256)
  #   gen.add("doc-a")                                          # => 0
  #   gen.add(EvidenceRecord::DataGroup.new([meta, body]))      # => 1
  #   req = gen.timestamp_request(nonce: SecureRandom.random_number(2**64))
  #   res = post_to_tsa(req.to_der)          # the TSA response, as a String
  #   records = gen.build(res)               # => [Record, Record], in add order
  #
  # The data are hashed when they are added and are not kept. Data cannot be
  # added once timestamp_request or build has been called, because the
  # time-stamp covers the hash tree at that point.
  #
  # build checks that the response is granted and matches the request, but
  # does not check its signature; verify the records for that.
  #
  # Not thread-safe.
  class Generator
    attr_reader :digest_algorithm

    # digest_algorithm: :sha256, :sha384 or :sha512.
    def initialize(digest_algorithm: :sha256)
      @digest_algorithm = DigestAlgorithm.fetch(digest_algorithm)
      @tree = HashTree.new(digest_algorithm: @digest_algorithm)
      @groups = []
      @closed = false
    end

    # Adds a data object (a String or a PrehashedData) or a DataGroup, and
    # returns its index: the position of its record in the result of build.
    def add(data)
      raise Error, "data cannot be added after timestamp_request or build" if @closed

      source = DataSource.wrap(data)
      index = @tree.add(source.member_digests(@digest_algorithm))
      @groups << source.group?
      index
    end

    # The number of data objects and groups added.
    def size
      @tree.size
    end

    # The root of the hash tree: the hash value to be time-stamped.
    def root
      raise Error, "no data has been added" if @tree.empty?

      @tree.root
    end

    # An OpenSSL::Timestamp::Request for the root, to be sent to a TSA. When
    # nonce or policy_id is given, build checks that the response has the
    # same values.
    def timestamp_request(nonce: nil, cert_requested: true, policy_id: nil)
      exchange.request(nonce: nonce, cert_requested: cert_requested, policy_id: policy_id)
    end

    # Builds the records from the TSA response (a String, or an
    # OpenSSL::Timestamp::Response). Returns an Array of Records in the order
    # the data were added. Raises TimestampResponseError when the response
    # is not usable.
    def build(response)
      timestamp = exchange.token(response)
      Array.new(size) { |i| Record.build([Chain.build([archive_timestamp(i, timestamp)])]) }
    end

    private

    def exchange
      @exchange ||= begin
        imprint = root
        @closed = true
        TimestampExchange.new(@digest_algorithm, imprint)
      end
    end

    # A single data object time-stamped alone needs no reduced hash tree: its
    # hash is the message imprint (as Bouncy Castle does).
    def archive_timestamp(index, timestamp)
      return ArchiveTimeStamp.build(timestamp: timestamp) if size == 1 && !@groups[0]

      ArchiveTimeStamp.build(timestamp: timestamp, reduced_hashtree: @tree.reduced_hashtree(index),
                             digest_algorithm: @digest_algorithm)
    end
  end
end
