# frozen_string_literal: true

module EvidenceRecord
  # Time-stamp validators: objects that check that a time-stamp token itself
  # is valid (docs/design.md 5.3).
  #
  # A validator responds to call(token, at:), where token is a TimeStampToken
  # and at is the Time at which the token must be valid. It returns a truthy
  # value when the token is valid. When it is not, it raises
  # EvidenceRecord::TimestampInvalidError or returns false or nil; both are
  # treated as invalid, so a validator that forgets to return true fails
  # closed. Other exceptions are not caught.
  module TimestampValidator
    # Checks the signature of the token and its certificate chain at the given
    # time with OpenSSL, using a store of trusted certificates.
    #
    #   store = OpenSSL::X509::Store.new
    #   store.add_cert(tsa_root)
    #   validator = EvidenceRecord::TimestampValidator::OpenSSL.new(store: store)
    #
    # What it checks: the signature, that the signing certificate is the one
    # named in the token (ESS signing certificate), that it may be used for
    # time-stamping, and that its chain to a trusted certificate is valid at
    # the given time.
    #
    # What it does not check: revocation (CRL / OCSP) unless the store is set
    # up for it, and whether the algorithms used are still considered secure.
    # Give your own validator for those.
    #
    # The store's verification time is set on every call, so do not share the
    # store with other code that relies on it.
    class OpenSSL
      def initialize(store:)
        unless store.is_a?(::OpenSSL::X509::Store)
          raise ArgumentError, "store must be an OpenSSL::X509::Store, got #{store.class}"
        end

        @store = store
      end

      def call(token, at:)
        raise ArgumentError, "token must be an EvidenceRecord::TimeStampToken" unless token.is_a?(TimeStampToken)
        raise ArgumentError, "at must be a Time, got #{at.class}" unless at.is_a?(Time)

        @store.time = at
        response_for(token).verify(request_for(token), @store)
        true
      rescue ::OpenSSL::Timestamp::TimestampError => e
        raise TimestampInvalidError, "invalid time-stamp: #{e.message}"
      end

      private

      # A request that the token must match. It is built from the token
      # itself: the hash chain has already been checked against the imprint.
      def request_for(token)
        request = ::OpenSSL::Timestamp::Request.new
        request.algorithm = token.hash_algorithm.name.to_s.upcase
        request.message_imprint = token.message_imprint.to_binary
        request.nonce = token.nonce if token.nonce
        request
      end

      # A granted TimeStampResp holding the token without its crls field
      # (docs/design.md 7.2).
      def response_for(token)
        status = DER.sequence([DER.encode_integer(0)])
        ::OpenSSL::Timestamp::Response.new(DER.sequence([status, token.der_without_crls]))
      end
    end
  end
end
