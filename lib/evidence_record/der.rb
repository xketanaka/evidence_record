# frozen_string_literal: true

module EvidenceRecord
  # Internal: a strict DER reader and the few encoders the library needs
  # (docs/design.md 7.1).
  #
  # OpenSSL::ASN1 is not used to check DER: re-encoding what it decoded keeps
  # indefinite lengths and constructed strings, does not reorder SETs, and
  # drops the fractional seconds of GeneralizedTime, so "decode and re-encode
  # gives the same bytes" accepts BER and rejects valid DER. This reader also
  # keeps the original bytes of every element, which are what gets hashed.
  module DER
    BOOLEAN = 1
    INTEGER = 2
    BIT_STRING = 3
    OCTET_STRING = 4
    NULL = 5
    OBJECT_IDENTIFIER = 6
    ENUMERATED = 10
    RELATIVE_OID = 13
    SEQUENCE = 16
    SET = 17
    UTC_TIME = 23
    GENERALIZED_TIME = 24

    # Universal types that are always constructed: EXTERNAL, EMBEDDED PDV,
    # SEQUENCE and SET. All others must use the primitive encoding in DER.
    CONSTRUCTED_TYPES = [8, 11, SEQUENCE, SET].freeze
    TAG_CLASSES = %i[universal application context private].freeze
    MAX_DEPTH = 64
    GENERALIZED_TIME_PATTERN = /\A(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(?:\.(\d*[1-9]))?Z\z/

    # One element (TLV). raw is its whole encoding, content its contents
    # octets; children is an Array of Nodes for a constructed element.
    class Node
      attr_reader :tag_class, :tag, :raw, :content, :children

      def initialize(tag_class, constructed, tag, raw, content, children)
        @tag_class = tag_class
        @constructed = constructed
        @tag = tag
        @raw = raw.freeze
        @content = content.freeze
        @children = children&.freeze
        freeze
      end

      def constructed?
        @constructed
      end

      def universal?(tag)
        @tag_class == :universal && @tag == tag
      end

      def context?(tag)
        @tag_class == :context && @tag == tag
      end
    end

    module_function

    # Parses one DER element that must span all of bytes. what names the
    # input in error messages.
    def parse(bytes, what)
      raise ArgumentError, "#{what} must be a String, got #{bytes.class}" unless bytes.is_a?(String)

      bytes = bytes.b
      node, pos = read(bytes, 0, bytes.bytesize, 0, what)
      raise ParseError, "#{what}: #{bytes.bytesize - pos} bytes of trailing data" unless pos == bytes.bytesize

      node
    end

    def read(bytes, pos, limit, depth, what)
      raise ParseError, "#{what}: nested too deeply" if depth > MAX_DEPTH

      start = pos
      id = byte_at(bytes, pos, limit, what)
      pos += 1
      tag_class = TAG_CLASSES[id >> 6]
      constructed = id.anybits?(0x20)
      tag = id & 0x1f
      tag, pos = read_high_tag(bytes, pos, limit, what) if tag == 0x1f
      length, pos = read_length(bytes, pos, limit, what)
      raise ParseError, "#{what}: truncated" if limit - pos < length

      children = nil
      if constructed
        children = []
        child_pos = pos
        while child_pos < pos + length
          child, child_pos = read(bytes, child_pos, pos + length, depth + 1, what)
          children << child
        end
      end
      node = Node.new(tag_class, constructed, tag, bytes.byteslice(start, pos + length - start),
                      bytes.byteslice(pos, length), children)
      check_universal(node, what) if tag_class == :universal
      [node, pos + length]
    end

    def byte_at(bytes, pos, limit, what)
      raise ParseError, "#{what}: truncated" if pos >= limit

      bytes.getbyte(pos)
    end

    def read_high_tag(bytes, pos, limit, what)
      tag = 0
      loop do
        b = byte_at(bytes, pos, limit, what)
        raise ParseError, "#{what}: non-minimal tag number" if tag.zero? && b == 0x80
        raise ParseError, "#{what}: tag number too large" if tag > 0xffffff

        tag = (tag << 7) | (b & 0x7f)
        pos += 1
        break if b < 0x80
      end
      raise ParseError, "#{what}: non-minimal tag number" if tag < 0x1f

      [tag, pos]
    end

    def read_length(bytes, pos, limit, what)
      first = byte_at(bytes, pos, limit, what)
      pos += 1
      return [first, pos] if first < 0x80
      raise ParseError, "#{what}: indefinite length is not allowed in DER" if first == 0x80

      count = first & 0x7f
      raise ParseError, "#{what}: length too large" if count > 4
      raise ParseError, "#{what}: truncated" if limit - pos < count

      length_bytes = bytes.byteslice(pos, count)
      length = length_bytes.unpack1("H*").to_i(16)
      if length_bytes.getbyte(0).zero? || length < 0x80
        raise ParseError, "#{what}: length is not in its shortest form"
      end

      [length, pos + count]
    end

    def check_universal(node, what)
      tag = node.tag
      raise ParseError, "#{what}: unexpected end-of-contents" if tag.zero?
      if node.constructed? != CONSTRUCTED_TYPES.include?(tag)
        raise ParseError, "#{what}: universal type #{tag} must use the " \
                          "#{node.constructed? ? 'primitive' : 'constructed'} encoding"
      end

      c = node.content
      ok = case tag
           when BOOLEAN then ["\x00".b, "\xff".b].include?(c)
           when INTEGER, ENUMERATED then minimal_integer?(c)
           when NULL then c.empty?
           when BIT_STRING then valid_bit_string?(c)
           when OBJECT_IDENTIFIER, RELATIVE_OID then valid_oid_content?(c)
           when SET then sorted?(node.children)
           when UTC_TIME then c.match?(/\A\d{12}Z\z/)
           when GENERALIZED_TIME then c.match?(GENERALIZED_TIME_PATTERN)
           else true
           end
      raise ParseError, "#{what}: invalid DER encoding of universal type #{tag}" unless ok
    end

    def minimal_integer?(c)
      return false if c.empty?
      return true if c.bytesize == 1

      a = c.getbyte(0)
      b = c.getbyte(1)
      !((a.zero? && b < 0x80) || (a == 0xff && b >= 0x80))
    end

    def valid_bit_string?(c)
      return false if c.empty?

      unused = c.getbyte(0)
      return unused.zero? if c.bytesize == 1

      unused <= 7 && (c.getbyte(-1) & ((1 << unused) - 1)).zero?
    end

    def valid_oid_content?(c)
      return false if c.empty? || c.getbyte(-1) >= 0x80

      # no subidentifier may start with 0x80 (a non-minimal encoding)
      c.each_byte.each_with_index.none? { |b, i| b == 0x80 && (i.zero? || c.getbyte(i - 1) < 0x80) }
    end

    # DER sorts the elements of a SET by their encodings (X.690 11.6).
    def sorted?(nodes)
      nodes.each_cons(2).all? { |a, b| (a.raw <=> b.raw) <= 0 }
    end

    # --- reading values ------------------------------------------------------

    def expect(node, what, tag)
      raise ParseError, "#{what}: expected universal type #{tag}" unless node&.universal?(tag)

      node
    end

    # The children of a SEQUENCE (or of the constructed element given by
    # context:), checking how many there are.
    def children_of(node, what, size: nil, context: nil)
      ok = node && node.constructed? &&
           (context ? node.context?(context) : node.universal?(SEQUENCE))
      raise ParseError, "#{what}: expected #{context ? "[#{context}]" : 'a SEQUENCE'}" unless ok
      if size && !(size === node.children.size)
        raise ParseError, "#{what}: unexpected number of elements (#{node.children.size})"
      end

      node.children
    end

    def oid(node, what)
      c = expect(node, what, OBJECT_IDENTIFIER).content
      ids = []
      value = 0
      c.each_byte do |b|
        value = (value << 7) | (b & 0x7f)
        next if b >= 0x80

        ids << value
        value = 0
      end
      first = [ids[0] / 40, 2].min
      [first, ids[0] - (first * 40), *ids[1..]].join(".")
    end

    def integer(node, what)
      c = expect(node, what, INTEGER).content
      value = c.unpack1("H*").to_i(16)
      c.getbyte(0) >= 0x80 ? value - (1 << (8 * c.bytesize)) : value
    end

    def octet_string(node, what)
      expect(node, what, OCTET_STRING).content
    end

    def generalized_time(node, what)
      m = GENERALIZED_TIME_PATTERN.match(expect(node, what, GENERALIZED_TIME).content)
      year, month, day, hour, minute, second = m.captures.first(6).map(&:to_i)
      fraction = m[7] ? Rational(m[7].to_i, 10**m[7].size) : 0
      time = Time.utc(year, month, day, hour, minute, second + fraction)
      unless [time.year, time.month, time.day, time.hour, time.min, time.sec] ==
             [year, month, day, hour, minute, second]
        raise ParseError, "#{what}: invalid time"
      end

      time
    rescue ArgumentError
      raise ParseError, "#{what}: invalid time"
    end

    # --- encoding --------------------------------------------------------------

    # A TLV with a one-byte identifier.
    def encode(identifier, content)
      [identifier].pack("C") + encode_length(content.bytesize) + content.b
    end

    def encode_length(length)
      return [length].pack("C") if length < 0x80

      bytes = [length.to_s(16).then { _1.size.odd? ? "0#{_1}" : _1 }].pack("H*")
      [0x80 | bytes.bytesize].pack("C") + bytes
    end

    def sequence(parts)
      encode(0x20 | SEQUENCE, parts.map(&:b).join)
    end

    # A constructed context-specific element [tag] (tag < 31).
    def context(tag, content)
      encode(0xa0 | tag, content)
    end

    def encode_octet_string(bytes)
      encode(OCTET_STRING, bytes)
    end

    def encode_integer(value)
      OpenSSL::ASN1::Integer.new(value).to_der
    end

    def encode_oid(dotted)
      OpenSSL::ASN1::ObjectId.new(dotted).to_der
    end
  end
end
