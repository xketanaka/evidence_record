# frozen_string_literal: true

require_relative "../test_helper"
require_relative "../support/test_tsa"
require_relative "../support/bouncy_castle"
require "tmpdir"

# Interoperability with Bouncy Castle in both directions (docs/design.md,
# chapter 9): records built and renewed here are verified by Bouncy Castle,
# and records built and renewed by Bouncy Castle are verified here.
#
# Run with `rake test:interop` after `rake test:fetch_bouncy_castle`; needs a
# JDK (java on PATH).
class BouncyCastleTest < Minitest::Test
  ER = EvidenceRecord

  H1 = "This is H1"
  H2 = "This is H2"
  H3 = ["This is H3A", "This is H3B", "This is H3C"].freeze

  def setup
    skip "java not found" unless BouncyCastle.java_available?
    skip "Bouncy Castle jars not found; run `rake test:fetch_bouncy_castle`" unless BouncyCastle.jars_available?

    @dir = Dir.mktmpdir("evidence_record-interop")
    @tsa = TestTSA.default
    @time = Time.now - 30
  end

  def teardown
    FileUtils.remove_entry(@dir) if @dir
  end

  # Time-stamps are made two seconds apart, ending before now. They are kept
  # close to now because OpenSSL::Timestamp::Factory puts the current time
  # in the signingTime attribute whatever the genTime, and Bouncy Castle
  # requires the two to be within 60 seconds (TimeStampToken#validate).
  def next_time
    @time += 2
  end

  def file(name, content)
    path = File.join(@dir, name)
    File.binwrite(path, content)
    path
  end

  # --- records made here, verified by Bouncy Castle --------------------------------------

  def respond(renewal_or_generator)
    @tsa.respond(renewal_or_generator.timestamp_request, gen_time: next_time).to_der
  end

  def timestamp_renewal(record, response = nil)
    renewal = record.timestamp_renewal
    renewal.build(response || respond(renewal))
  end

  def hash_tree_renewal(record, data, alg)
    renewal = record.hash_tree_renewal(data: data, digest_algorithm: alg)
    renewal.build(respond(renewal))
  end

  # name => [record, the data it covers, data that it does not cover,
  #          the data as given to Bouncy Castle (if different)]
  #
  # Bouncy Castle cannot check a data group of one member as a group: it
  # requires the first partial hash tree of a group to hold several values
  # (ERSArchiveTimeStamp#checkContainsHashValue). Such a group has the same
  # hash as its member alone, so the member is given as a data object.
  def records_made_here
    group = ER::DataGroup.new(H3)
    gen = ER::Generator.new(digest_algorithm: :sha256)
    [H1, H2, group].each { gen.add(_1) }
    init = gen.build(respond(gen))

    gen = ER::Generator.new(digest_algorithm: :sha384)
    gen.add(H1)
    single, = gen.build(respond(gen))

    gen = ER::Generator.new(digest_algorithm: :sha512)
    [H1, ER::DataGroup.new([H2]), "x", "y"].each { gen.add(_1) }
    small_group = gen.build(respond(gen))[1]

    renewal = init[2].timestamp_renewal
    shared = respond(renewal)
    ts2 = timestamp_renewal(renewal.build(shared))
    ts0 = init[0].timestamp_renewal.build(shared)

    {
      "init-0" => [init[0], H1, H2],
      "init-1" => [init[1], H2, H1],
      "init-2" => [init[2], group, ER::DataGroup.new(H3.first(2))],
      "single" => [single, H1, H2],
      "small-group" => [small_group, ER::DataGroup.new([H2]), H1, H2],
      "ts-0" => [ts0, H1, H2],
      "ts-2" => [ts2, group, H1],
      "hash-0" => [timestamp_renewal(hash_tree_renewal(ts0, H1, :sha512)), H1, H2],
      "hash-2" => [timestamp_renewal(hash_tree_renewal(ts2, group, :sha384)), group, H1],
    }
  end

  def manifest_line(record_path, data)
    kind, members = data.is_a?(ER::DataGroup) ? ["group", data.members] : ["object", [data]]
    paths = members.map { file("data-#{_1.unpack1('H*')}", _1) }
    [record_path, @cert_path, kind, *paths].join(" ")
  end

  # このライブラリで生成・更新した Evidence Record を、Bouncy Castle で検証する。
  #
  # records_made_here の各 ER（生成、タイムスタンプ更新、ハッシュツリー更新）について、
  # - まずこのライブラリ自身で検証できることを確認する
  # - Bouncy Castle（ErsInterop.java verify）で、対象のデータなら検証に成功し（OK）、
  #   別のデータなら失敗する（NG）ことを確認する
  # Bouncy Castle 側では、ER の読み込み時の Chain の確認、validatePresent（データが含まれるか）、
  # validate（最後のタイムスタンプの署名）に加えて、Bouncy Castle が DER で書き直した
  # バイト列が元と一致すること（DER の互換性）も確認している。
  def test_records_made_here_verify_with_bouncy_castle
    @cert_path = file("tsa.cer", @tsa.certificate.to_der)
    records = records_made_here
    lines = []
    validator = ER::TimestampValidator::OpenSSL.new(store: @tsa.store)
    records.each do |name, (record, data, other, bc_data)|
      assert record.verify!(data: data, timestamp_validator: validator), name
      path = file("#{name}.ers", record.to_der)
      lines << manifest_line(path, bc_data || data) << manifest_line(path, other)
    end
    results = BouncyCastle.run("verify", file("manifest", lines.join("\n"))).lines(chomp: true)

    expected = records.keys.flat_map { ["#{_1}: OK", "#{_1} (other data): NG"] }
    actual = records.keys.each_with_index.flat_map do |name, i|
      ["#{name}: #{results[2 * i]}", "#{name} (other data): #{results[(2 * i) + 1]&.slice(0, 2)}"]
    end
    assert_equal expected, actual
  end

  # --- records made by Bouncy Castle, verified here ----------------------------------------

  # Bouncy Castle で生成・更新した Evidence Record を、このライブラリで検証する。
  #
  # Bouncy Castle（ErsInterop.java generate）が、自前のテスト用 TSA で作った ER
  # （生成、単独のデータ、応答を使い回したタイムスタンプ更新、SHA-512 へのハッシュツリー更新）
  # について、
  # - Chain と ArchiveTimeStamp の数が想定どおりであること
  # - 対象のデータなら、署名の検証まで含めて verify! に成功すること
  # - 別のデータなら verify が false になること
  # を確認する。
  def test_records_made_by_bouncy_castle_verify_here
    BouncyCastle.run("generate", @dir)
    store = OpenSSL::X509::Store.new
    store.add_cert(OpenSSL::X509::Certificate.new(File.binread(File.join(@dir, "root.cer"))))
    validator = ER::TimestampValidator::OpenSSL.new(store: store)
    read = ->(name) { File.binread(File.join(@dir, name)) }
    h1, h2 = read.("h1.bin"), read.("h2.bin")
    group = ER::DataGroup.new(%w[h3a h3b h3c].map { read.("#{_1}.bin") })
    assert_equal [H1, H2], [h1, h2]
    assert_equal H3, group.members

    {
      "init-0" => [h1, h2, [1]], "init-1" => [h2, h1, [1]], "init-2" => [group, h1, [1]],
      "single" => [h1, h2, [1]], "ts-0" => [h1, h2, [2]], "ts-2" => [group, h1, [3]],
      "hash-0" => [h1, h2, [2, 2]], "hash-2" => [group, h1, [3, 2]],
    }.each do |name, (data, other, shape)|
      record = ER::Record.from_der(read.("#{name}.ers"))
      assert_equal shape, record.chains.map { _1.archive_timestamps.size }, name
      assert record.verify!(data: data, timestamp_validator: validator), name
      refute record.verify(data: other, timestamp_validator: validator), name
    end
  end

  # タイムスタンプを付ける値（ハッシュツリーのルート）が、Bouncy Castle とこのライブラリで
  # 一致することを確認する。一致すれば、一方の要求に対する TSA の応答を他方でも使える。
  #
  # Bouncy Castle が作った ER のタイムスタンプの messageImprint と、同じデータや同じ ER から
  # このライブラリで計算した値を、次の 3 つについて比べる。
  # - 生成: Generator#root
  # - タイムスタンプ更新: TimestampRenewal#root（init-2 を更新した ts-2 の 2 つ目のタイムスタンプ）
  # - ハッシュツリー更新: HashTreeRenewal#root（ts-2 を更新した hash-2 の 2 つ目の Chain）
  def test_same_roots_as_bouncy_castle
    BouncyCastle.run("generate", @dir)
    bc = ER::Record.from_der(File.binread(File.join(@dir, "init-0.ers")))
    gen = ER::Generator.new(digest_algorithm: :sha256)
    [H1, H2, ER::DataGroup.new(H3)].each { gen.add(_1) }
    assert_equal bc.chains[0].archive_timestamps[0].timestamp.message_imprint, gen.root

    renewed = ER::Record.from_der(File.binread(File.join(@dir, "ts-2.ers")))
    before = ER::Record.from_der(File.binread(File.join(@dir, "init-2.ers")))
    assert_equal renewed.chains[0].archive_timestamps[1].timestamp.message_imprint, before.timestamp_renewal.root
    renewed2 = ER::Record.from_der(File.binread(File.join(@dir, "hash-2.ers")))
    ts2 = ER::Record.from_der(File.binread(File.join(@dir, "ts-2.ers")))
    assert_equal renewed2.chains[1].archive_timestamps[0].timestamp.message_imprint,
                 ts2.hash_tree_renewal(data: ER::DataGroup.new(H3), digest_algorithm: :sha512).root
  end
end
