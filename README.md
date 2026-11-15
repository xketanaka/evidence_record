# evidence_record

[RFC 4998](https://www.rfc-editor.org/rfc/rfc4998)（Evidence Record Syntax, ERS）に準拠した、Evidence Record の Ruby 実装。

Evidence Record とは、データがある時点に存在しそれ以降改ざんされてないことを長期間にわたって証明するデータ構造。多数のデータをハッシュツリーにまとめてタイムスタンプ(RFC 3161)で保護する。タイムスタンプやハッシュアルゴリズムがが弱くなる前に新しいタイムスタンプやハッシュアルゴリズムに更新することができる。

## 機能

- 文字列または計算済みのハッシュ値を対象に Evidence Record を生成
- 多数のデータの Evidence Record を、1 つのタイムスタンプでまとめて生成
- タイムスタンプ更新(TSA の証明書の期限が切れる前にタイムスタンプを掛け直す)、ハッシュツリー更新(新しいハッシュアルゴリズムに移行する)
- 外部から与えられた Evidence Record の検証。任意のハッシュツリーを RFC 4998 の手順で検証する
- タイムスタンプの検証は差し替え可能。OpenSSL で署名と証明書チェーンを検証する検証器を同梱
- TSA との通信は行わない
- [BSI のテストデータ](https://github.com/bcgit/bc-test-data)で動作を確認済み。[Bouncy Castle](https://www.bouncycastle.org/) と双方向に相互運用できることを確認済み
- 依存ライブラリなし

## インストール

```bash
gem install evidence_record

# or

bundle add evidence_record
```

## 使い方

### 生成

```ruby
gen = EvidenceRecord::Generator.new(digest_algorithm: :sha256)
gen.add("doc-a")
gen.add(EvidenceRecord::DataGroup.new([meta_xml, body_pdf]))  # グループは 1 つの Evidence Record になる

# タイムスタンプ要求(OpenSSL::Timestamp::Request)を作り、TSA に送る
req = gen.timestamp_request(nonce: SecureRandom.random_number(2**64))
res = post_to_tsa(req.to_der)   # res: TSA の応答(TimeStampResp のバイト列)

# add した順に Evidence Record が返る
records = gen.build(res)        # => [Record, Record]
File.binwrite("doc-a.ers", records[0].to_der)
```

タイムスタンプ取得(post_to_tsa)の実装例

```ruby
def post_to_tsa(der)
  uri = URI("https://tsa.example.com/")
  res = Net::HTTP.post(uri, der, "Content-Type" => "application/timestamp-query")
  raise "TSA error: #{res.code}" unless res.is_a?(Net::HTTPSuccess)

  res.body
end
```

### 検証

```ruby
record = EvidenceRecord::Record.from_der(File.binread("doc-a.ers"))

# TSA の証明書チェーンを検証する
store = OpenSSL::X509::Store.new
store.add_cert(tsa_root_certificate)
validator = EvidenceRecord::TimestampValidator::OpenSSL.new(store: store)

record.verify(data: "doc-a", timestamp_validator: validator)    # => true / false
record.verify!(data: "doc-a", timestamp_validator: validator)   # 失敗すると例外
record.proven_time                                              # データの存在が証明される時刻(タイムスタンプの genTime)
```

検証では、データからすべてのタイムスタンプまでのハッシュの連鎖、各タイムスタンプの正当性を確認する。

### タイムスタンプ更新

TSA の証明書の期限が切れる前にタイムスタンプを掛け直す

```ruby
renewal = record.timestamp_renewal
req     = renewal.timestamp_request(nonce: SecureRandom.random_number(2**64))
record2 = renewal.build(post_to_tsa(req.to_der))   # => 新しい Record
```

### ハッシュツリー更新

使っているハッシュアルゴリズムが弱くなった際に新しいアルゴリズムに移行する。データが必要。

```ruby
renewal = record.hash_tree_renewal(data: "doc-a", digest_algorithm: :sha512)
req     = renewal.timestamp_request(nonce: SecureRandom.random_number(2**64))
record3 = renewal.build(post_to_tsa(req.to_der))   # => 新しい Chain が追加された Record
```

### 計算済みのハッシュ値

データ本体の代わりにあらかじめ手計算したハッシュ値を指定可能。

```ruby
pre = EvidenceRecord::PrehashedData.new(
  sha256: OpenSSL::Digest.new("SHA256").file("large.bin").digest,
  sha512: OpenSSL::Digest.new("SHA512").file("large.bin").digest,
)
gen.add(pre)
record.verify(data: pre, timestamp_validator: validator)
record.hash_tree_renewal(data: pre, digest_algorithm: :sha512)
```

### Evidence Record の内容確認

```ruby
record.chains.each do |chain|
  chain.archive_timestamps.each do |ats|
    ts = ats.timestamp
    puts "#{ats.digest_algorithm} #{ts.gen_time} serial=#{ts.serial_number}"
  end
end

# 最後のタイムスタンプの TSA 証明書の期限を調べる
last = record.chains.last.archive_timestamps.last.timestamp
last.certificates.map(&:not_after)
```

### 参照

- 各クラス・メソッドの仕様は [docs/reference.md](docs/reference.md) を参照

## 開発

```bash
bundle install
bundle exec rake test
```

BSI のテストデータを使うテストは、データをダウンロードしてから実行する。
テストデータは [bcgit/bc-test-data](https://github.com/bcgit/bc-test-data) の `tsp/20170316_Testdaten` (BSI TR-ESOR / ERS テストツール)から固定したコミットのものを取得し、SHA-256 で内容を確認する。

```bash
bundle exec rake test:fetch_vectors   # test/fixtures/bsi に取得する
```

Bouncy Castle との相互運用テストには JDK が必要。Bouncy Castle は Maven Central から固定したバージョンのものを取得し、SHA-256 で内容を確認する。

```bash
bundle exec rake test:fetch_bouncy_castle   # interop/lib に取得する
bundle exec rake test:interop
```

Docker を使う場合：

```bash
docker compose run --rm test        # Ruby 4.0
docker compose run --rm test-3.4    # Ruby 3.4
docker compose run --rm test bundle exec rake test:fetch_vectors
docker compose run --rm interop     # Bouncy Castle との相互運用テスト（JDK 入りのイメージ）
```

## ライセンス

[MIT License](LICENSE.txt)
