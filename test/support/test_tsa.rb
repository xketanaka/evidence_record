# frozen_string_literal: true

require "openssl"

# A local time-stamping authority for tests, built on
# OpenSSL::Timestamp::Factory: a root CA and a TSA certificate issued by it.
class TestTSA
  attr_reader :root, :certificate

  def self.default
    @default ||= new
  end

  def initialize(now: Time.now)
    @root_key = OpenSSL::PKey::EC.generate("prime256v1")
    @root = issue("CN=evidence_record test root", @root_key, @root_key, nil, now, ca: true)
    @key = OpenSSL::PKey::EC.generate("prime256v1")
    @certificate = issue("CN=evidence_record test TSA", @key, @root_key, @root, now, ca: false)
    @serial = 0
  end

  def store
    OpenSSL::X509::Store.new.tap { _1.add_cert(@root) }
  end

  def request(imprint, algorithm: "SHA256", nonce: nil)
    req = OpenSSL::Timestamp::Request.new
    req.algorithm = algorithm
    req.message_imprint = imprint
    req.nonce = nonce if nonce
    req.cert_requested = true
    req
  end

  # A time-stamp response for request (an OpenSSL::Timestamp::Request).
  def respond(request, gen_time: Time.now)
    factory = OpenSSL::Timestamp::Factory.new
    factory.gen_time = gen_time
    factory.serial_number = (@serial += 1)
    factory.allowed_digests = %w[SHA1 SHA256 SHA384 SHA512] # SHA1 for testing rejection
    factory.default_policy_id = "1.3.6.1.4.1.99999.1"
    factory.additional_certs = [@root]
    factory.create_timestamp(@key, @certificate, request)
  end

  # The DER of a time-stamp token over imprint.
  def token_der(imprint, algorithm: "SHA256", gen_time: Time.now)
    respond(request(imprint, algorithm: algorithm), gen_time: gen_time).token.to_der
  end

  private

  def issue(subject, key, issuer_key, issuer, now, ca:)
    cert = OpenSSL::X509::Certificate.new
    cert.version = 2
    cert.serial = OpenSSL::BN.rand(64)
    cert.subject = OpenSSL::X509::Name.parse(subject)
    cert.issuer = issuer ? issuer.subject : cert.subject
    cert.public_key = key
    cert.not_before = now - 3600
    cert.not_after = now + (365 * 24 * 3600)
    ext = OpenSSL::X509::ExtensionFactory.new
    ext.subject_certificate = cert
    ext.issuer_certificate = issuer || cert
    if ca
      cert.add_extension(ext.create_extension("basicConstraints", "CA:TRUE", true))
      cert.add_extension(ext.create_extension("keyUsage", "keyCertSign,cRLSign", true))
    else
      cert.add_extension(ext.create_extension("extendedKeyUsage", "timeStamping", true))
      cert.add_extension(ext.create_extension("keyUsage", "digitalSignature", true))
    end
    cert.sign(issuer_key, "SHA256")
    cert
  end
end
