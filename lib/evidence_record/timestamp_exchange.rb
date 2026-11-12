# frozen_string_literal: true

module EvidenceRecord
  # Internal: one exchange with a TSA for a hash value (docs/design.md 3.3,
  # 6). Makes the request and takes the time-stamp token out of the response
  # after checking it. Used by Generator and the renewals.
  class TimestampExchange
    GRANTED = 0
    GRANTED_WITH_MODS = 1

    def initialize(algorithm, imprint)
      @algorithm = algorithm
      @imprint = Digest.wrap(imprint)
    end

    # An OpenSSL::Timestamp::Request for the hash value. The nonce and policy
    # given here are checked against the response in #token.
    def request(nonce: nil, cert_requested: true, policy_id: nil)
      raise ArgumentError, "nonce must be an Integer, got #{nonce.class}" unless nonce.nil? || nonce.is_a?(Integer)
      unless policy_id.nil? || policy_id.is_a?(String)
        raise ArgumentError, "policy_id must be a String (OID), got #{policy_id.class}"
      end

      @nonce = nonce
      @policy_id = policy_id
      request = OpenSSL::Timestamp::Request.new
      request.algorithm = @algorithm.name.to_s.upcase
      request.message_imprint = @imprint.to_binary
      request.nonce = nonce if nonce
      request.policy_id = policy_id if policy_id
      request.cert_requested = cert_requested ? true : false
      request
    end

    # The TimeStampToken in response: a String (the TimeStampResp as
    # returned by the TSA) or an OpenSSL::Timestamp::Response. Lengths encoded
    # as BER are rewritten as DER; anything else that is not DER is rejected
    # (docs/design.md 6). Raises TimestampResponseError when the response
    # cannot be used.
    #
    # The signature is not checked here; verify the resulting record.
    def token(response)
      token = extract(response_bytes(response))
      check!(token)
      token
    end

    private

    def response_bytes(response)
      case response
      when String then response
      when OpenSSL::Timestamp::Response then response.to_der
      else
        raise ArgumentError,
              "response must be a String or an OpenSSL::Timestamp::Response, got #{response.class}"
      end
    end

    # TimeStampResp ::= SEQUENCE { status PKIStatusInfo,
    #   timeStampToken TimeStampToken OPTIONAL }
    # PKIStatusInfo ::= SEQUENCE { status PKIStatus,
    #   statusString PKIFreeText OPTIONAL, failInfo PKIFailureInfo OPTIONAL }
    def extract(bytes)
      node = DER.parse(DER.normalize_lengths(bytes, "time-stamp response"), "time-stamp response")
      status_info, token = DER.children_of(node, "time-stamp response", size: 1..2)
      status, *details = DER.children_of(status_info, "time-stamp response status", size: 1..3)
      code = DER.integer(status, "time-stamp response status")
      unless [GRANTED, GRANTED_WITH_MODS].include?(code)
        raise TimestampResponseError, "the TSA rejected the request (status #{code}#{status_text(details)})"
      end
      raise TimestampResponseError, "the response has no time-stamp token" unless token

      TimeStampToken.from_node(token, "time-stamp token")
    rescue ParseError => e
      raise TimestampResponseError, "invalid time-stamp response: #{e.message}"
    end

    # PKIFreeText ::= SEQUENCE SIZE (1..MAX) OF UTF8String
    def status_text(details)
      text = details.find { _1.universal?(DER::SEQUENCE) }
      return "" unless text

      strings = text.children.select { _1.universal?(12) }.map { _1.content.dup.force_encoding(Encoding::UTF_8).scrub }
      strings.empty? ? "" : ": #{strings.join('; ')}"
    end

    def check!(token)
      unless token.hash_algorithm_oid == @algorithm.oid
        raise TimestampResponseError,
              "the time-stamp uses hash algorithm #{token.hash_algorithm_oid}, but #{@algorithm} was requested"
      end
      unless token.message_imprint == @imprint
        raise TimestampResponseError, "the message imprint of the time-stamp does not match the request"
      end
      if @nonce && token.nonce != @nonce
        raise TimestampResponseError, "the nonce of the time-stamp does not match the request"
      end
      return unless @policy_id && token.policy_id != @policy_id

      raise TimestampResponseError, "the policy of the time-stamp does not match the request"
    end
  end
end
