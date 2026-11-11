# frozen_string_literal: true

require_relative "test_helper"

class HashTreeTest < Minitest::Test
  include VectorHelper

  DA = EvidenceRecord::DigestAlgorithm

  def h(data, alg = "SHA256")
    OpenSSL::Digest.digest(alg, data)
  end

  def tree_of(leaves, digest_algorithm: :sha256)
    alg = DA.fetch(digest_algorithm).name.to_s.upcase
    tree = EvidenceRecord::HashTree.new(digest_algorithm: digest_algorithm)
    leaves.each { |l| tree.add(l.is_a?(Array) ? l.map { h(_1, alg) } : [h(l, alg)]) }
    tree
  end

  # Expected roots from Bouncy Castle's ERSTest (bc-java,
  # pkix/src/test/java/org/bouncycastle/tsp/test/ERSTest.java, MIT License).
  BC_H3 = ["This is H3A", "This is H3B", "This is H3C"].freeze
  BC_H5 = ["This is H5A", "This is H5B", "This is H5C"].freeze
  BC_VECTORS = {
    "testBasicBuild" => [["This is H1", "This is H2", BC_H3],
                         "98fbf91c1aebdfec514d4a76532ec95f27ebcf4c8b6f7e2947afcbbfe7084cd4"],
    "testBuildMultiGroups" => [["This is H1", "This is H2", BC_H3, BC_H5],
                               "06836dfdec4b556e05535d5696b0e4add5cee7d765bcba1f4c1613ddb9176813"],
    "test4NodeBuild" => [["This is H1", "This is H2", BC_H3, "This is H4"],
                         "d82fea0eaff4b12925a201dff2332965953ca38c1eef6c9e31b55bbce4ce2984"],
    "testBuildMulti" => [["This is H1", "This is H2", BC_H3, "This is H4", BC_H5],
                         "b7efd5e742df672584e69b36ba5592748f841cc400ef989180aa2a69e43499e8"],
  }.freeze

  def test_roots_match_bouncy_castle
    BC_VECTORS.each do |name, (leaves, root)|
      assert_equal root, tree_of(leaves).root.to_hex, name
    end
  end

  def test_reduced_hashtrees_recompute_the_root
    rng = Random.new(42)
    (1..40).each do |n|
      leaves = Array.new(n) do |i|
        rng.rand(4).zero? ? Array.new(1 + rng.rand(4)) { "g#{i}-#{_1}" } : "d#{i}"
      end
      %i[sha256 sha512].each do |alg|
        tree = tree_of(leaves, digest_algorithm: alg)
        n.times do |i|
          rht = tree.reduced_hashtree(i)
          assert_equal tree.root, rht.root(alg), "n=#{n} i=#{i} #{alg}"
          assert_equal tree.leaf_hash(i), EvidenceRecord::ReducedHashtree.new([rht.leaf_values]).root(alg)
        end
      end
    end
  end

  def test_root_matches_naive_reference
    rng = Random.new(7)
    (1..40).each do |n|
      leaves = Array.new(n) { |i| rng.rand(3).zero? ? ["a#{i}", "b#{i}"] : "d#{i}" }
      assert_equal reference_root(leaves), tree_of(leaves).root.to_binary, "n=#{n}"
    end
  end

  # Written from docs/design.md 4.2: sort the leaf hashes, then repeatedly
  # hash adjacent pairs (sorted), carrying an odd last node up unchanged.
  def reference_root(leaves)
    node = ->(values) { values.size == 1 ? values[0] : h(values.sort.join) }
    level = leaves.map { |l| node.(l.is_a?(Array) ? l.map { h(_1) } : [h(l)]) }.sort
    level = level.each_slice(2).map { |s| s.size == 2 ? h(s.sort.join) : s[0] } until level.size == 1
    level[0]
  end

  def test_single_leaf
    tree = tree_of(["only"])
    assert_equal h("only"), tree.root.to_binary
    assert_equal [[EvidenceRecord::Digest.new(h("only"))]], tree.reduced_hashtree(0).partial_hashtrees
  end

  def test_group_leaf_contains_all_members
    tree = tree_of(["x", %w[m1 m2 m3]])
    rht = tree.reduced_hashtree(1)
    assert_equal %w[m1 m2 m3].map { h(_1) }, rht.leaf_values.map(&:to_binary)
    assert_equal h(%w[m1 m2 m3].map { h(_1) }.sort.join), tree.leaf_hash(1).to_binary
  end

  def test_duplicate_leaves_each_get_a_reduced_hashtree
    tree = tree_of(%w[same same other])
    3.times { |i| assert_equal tree.root, tree.reduced_hashtree(i).root(:sha256) }
  end

  def test_adding_after_root_rebuilds
    tree = tree_of(%w[a b])
    before = tree.root
    tree.add([h("c")])
    refute_equal before, tree.root
    assert_equal tree.root, tree.reduced_hashtree(2).root(:sha256)
  end

  def test_argument_errors
    tree = EvidenceRecord::HashTree.new
    assert_raises(EvidenceRecord::Error) { tree.root }
    assert_raises(ArgumentError) { tree.add([]) }
    assert_raises(ArgumentError) { tree.add(h("x")) }
    assert_raises(ArgumentError) { tree.add(["short"]) }
    assert_raises(ArgumentError) { tree.add([h("x", "SHA512")]) }
    tree.add([h("x")])
    assert_raises(IndexError) { tree.reduced_hashtree(1) }
    assert_raises(ArgumentError) { tree.reduced_hashtree("0") }
    assert_raises(EvidenceRecord::UnsupportedAlgorithmError) { EvidenceRecord::HashTree.new(digest_algorithm: :sha1) }
  end
end

class ReducedHashtreeTest < Minitest::Test
  include VectorHelper

  RHT = EvidenceRecord::ReducedHashtree

  def h(data)
    OpenSSL::Digest.digest("SHA256", data)
  end

  def hs(*values)
    h(values.sort.join)
  end

  # RFC 4998 §4.2 Figure 1/2: data groups 1 and 3 hold one document, data
  # group 2 holds three. The reduced hash tree for h2b is
  # [[h2a, h2b, h2c], [h1], [h3]].
  def test_rfc4998_example
    h1, h2a, h2b, h2c, h3 = %w[d1 d2a d2b d2c d3].map { h(_1) }
    h2abc = hs(h2a, h2b, h2c)
    h123 = hs(hs(h1, h2abc), h3)
    assert_equal h123, RHT.new([[h2a, h2b, h2c], [h1], [h3]]).root(:sha256).to_binary
    assert_equal h123, RHT.new([[h1], [h2abc], [h3]]).root(:sha256).to_binary
    assert_equal h123, RHT.new([[h3], [hs(h1, h2abc)]]).root(:sha256).to_binary
  end

  def test_n_ary_levels_hash_all_values_together
    a, b, c, d = %w[a b c d].map { h(_1) }
    # a 3-ary node above the leaf: H(sort(a, b, c)), then with d
    assert_equal hs(hs(a, b, c), d), RHT.new([[a], [b, c], [d]]).root(:sha256).to_binary
  end

  def test_single_value_is_used_as_is
    a = h("a")
    assert_equal a, RHT.new([[a]]).root(:sha256).to_binary
  end

  def test_value_object
    a = h("a")
    x = RHT.new([[a], [h("b")]])
    y = RHT.new([[EvidenceRecord::Digest.new(a)], [h("b")]])
    assert_equal x, y
    assert_equal x.hash, y.hash
    assert x.frozen?
    assert x.partial_hashtrees.frozen?
    assert_equal [EvidenceRecord::Digest.new(a)], x.leaf_values
  end

  def test_validation
    assert_raises(ArgumentError) { RHT.new([]) }
    assert_raises(ArgumentError) { RHT.new([[]]) }
    assert_raises(ArgumentError) { RHT.new([h("a")]) }
    assert_raises(ArgumentError) { RHT.new([[1]]) }
  end

  # The reduced hash trees in the BSI test vectors (binary and n-ary trees,
  # SHA-256/384/512) recompute the message imprint of their time-stamps.
  def test_bsi_vectors
    require_bsi_vectors!
    checked = 0
    BSIVectors::FILES.each_key.grep(/\.ers\z/).each do |relative|
      next if relative.include?("NOK")

      raw_archive_timestamps(BSIVectors.read(relative)).each do |alg_oid, partials, imprint|
        next unless partials

        alg = EvidenceRecord::DigestAlgorithm.from_oid(alg_oid)
        assert_equal imprint, RHT.new(partials).root(alg).to_binary, relative
        checked += 1
      end
    end
    assert_operator checked, :>=, 10
  end

  # A minimal reader written for this test, independent of the library's
  # ASN.1 layer: yields [digest algorithm OID, partial hash trees, imprint].
  def raw_archive_timestamps(der)
    chains = OpenSSL::ASN1.decode(der).value.last.value
    chains.flat_map(&:value).map do |ats|
      alg_oid = "2.16.840.1.101.3.4.2.1"
      partials = nil
      ats.value.each do |f|
        next unless f.tag_class == :CONTEXT_SPECIFIC

        alg_oid = f.value[0].oid if f.tag == 0
        partials = f.value.map { |p| p.value.map(&:value) } if f.tag == 2
      end
      signed_data = ats.value.last.value[1].value[0]
      tst_info = OpenSSL::ASN1.decode(signed_data.value[2].value[1].value[0].value)
      [alg_oid, partials, tst_info.value[2].value[1].value]
    end
  end
end
