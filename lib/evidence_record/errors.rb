# frozen_string_literal: true

module EvidenceRecord
  # Base class of all errors raised by this library.
  # Invalid arguments are reported with the standard ArgumentError instead.
  class Error < StandardError; end

  # The input is not valid DER, or does not match the RFC 4998 structures.
  class ParseError < Error; end

  # A hash algorithm that this library does not support (only SHA-256,
  # SHA-384 and SHA-512 are supported).
  class UnsupportedAlgorithmError < Error; end

  # The time-stamp response from a TSA cannot be used: it was rejected, or its
  # message imprint does not match the request.
  class TimestampResponseError < Error; end

  # Raised by verify! when an Evidence Record does not verify.
  #
  # chain_index and ats_index tell where the verification failed. They are nil
  # when the failure is not tied to a specific ArchiveTimeStamp.
  class VerificationError < Error
    attr_reader :chain_index, :ats_index

    def initialize(message = nil, chain_index: nil, ats_index: nil)
      super(message)
      @chain_index = chain_index
      @ats_index = ats_index
    end
  end

  # The Evidence Record is structurally invalid: an empty chain, mixed hash
  # algorithms within a chain, and so on.
  class MalformedRecordError < VerificationError; end

  # The data is not covered by the Evidence Record, or a computed root does not
  # match the message imprint of its time-stamp.
  class HashMismatchError < VerificationError; end

  # The time-stamp validator rejected a time-stamp token.
  class TimestampInvalidError < VerificationError; end
end
