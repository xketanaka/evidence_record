# evidence_record 設計メモ（草案）

RFC 4998（Evidence Record Syntax, ERS）の Ruby 実装について、設計上の判断とその理由を記録する。

姉妹 gem の [ct_merkle](../ct_merkle/docs/design.md)（RFC 6962 / RFC 9162）の方針を基本的に引き継ぎ、Bouncy Castle（bc-java）の `org.bouncycastle.tsp.ers` を機能・API の参考にした。各クラス・メソッドの仕様は、実装後に `reference.md` にまとめる。この文書は「なぜそうしたか」を残すためのもの。

> 草案のため、クラス名・メソッド名は仮のものを含む。未決事項は 11 章にまとめた。

## 1. 基本方針

- **ct_merkle の方針を引き継ぐ**
  - 生成と検証を分離する
  - ハッシュ値は内部ではバイナリで持ち、公開 API では `Digest` で返す
  - 検証は `verify`（true / false）と `verify!`（例外）の 2 本立てにする
  - 依存は標準ライブラリだけにする
- **v1 の範囲は、生成・タイムスタンプ更新・ハッシュツリー更新・検証**とする（Bouncy Castle と同じ）
- **TSA とは通信しない**: タイムスタンプ要求（`OpenSSL::Timestamp::Request`）を作り、応答（`OpenSSL::Timestamp::Response`）を受け取る 2 段階の API にする。HTTP などでの送受信は利用者に任せる（3.3）
- **検証は RFC の汎用手順で行う**: 生成するツリーの形（2 分木）に依存せず、他の実装が作った任意の形（n 分木）の Evidence Record を検証できるようにする（5.2）
- **元のバイト列を保持する**: 更新や検証でハッシュする対象（timeStamp、ArchiveTimeStampSequence）は、読み込んだときの DER をそのまま使う。再エンコードしたものは使わない（7.1）
- **値オブジェクトは不変にする**: 更新は元の Evidence Record を変更せず、新しいオブジェクトを返す（Bouncy Castle の `EvidenceRecord#addArchiveTimeStamp` と同じ）

## 2. 用語

| 用語 | 意味 |
|---|---|
| データオブジェクト | 存在を証明したい 1 件のデータ（バイト列） |
| データオブジェクトグループ | 1 つの Evidence Record でまとめて証明する、複数のデータオブジェクト（例：文書本体とメタデータ） |
| ハッシュツリー | 複数のデータオブジェクトのハッシュをまとめ、1 つのルートハッシュにする木。ノードのハッシュは、子のハッシュをバイナリ昇順にソートして連結したもののハッシュ |
| PartialHashtree | ハッシュツリーのある段で、一緒にハッシュされる値の集合 |
| Reduced Hash Tree | あるデータオブジェクトから、ルートを再計算するのに必要な PartialHashtree の列 |
| ATS（ArchiveTimeStamp） | Reduced Hash Tree と、そのルートに対するタイムスタンプ（RFC 3161 の TimeStampToken）の組 |
| ATS Chain（ArchiveTimeStampChain） | 同じハッシュアルゴリズムの ATS の列。後ろの ATS は、前の ATS の timeStamp を対象に含む（タイムスタンプ更新） |
| ATS Sequence（ArchiveTimeStampSequence） | ATS Chain の列。新しい Chain は、データと、それまでの Sequence の両方を対象に含む（ハッシュツリー更新） |
| Evidence Record（ER） | 1 つのデータオブジェクト（またはグループ）についての、ATS Sequence 全体 |
| タイムスタンプ更新 | タイムスタンプの署名アルゴリズムや証明書が危殆化する前に、直前のタイムスタンプに新しいタイムスタンプをかけること（RFC 4998 §5.2） |
| ハッシュツリー更新 | ハッシュアルゴリズムが危殆化する前に、新しいアルゴリズムでデータと Sequence をハッシュし直すこと（RFC 4998 §5.2） |
| 証明時刻 | ER が存在を証明する時刻。最初の ATS の genTime |

## 3. API の設計

### 3.1 階層

| 層 | 主なクラス | 役割 |
|---|---|---|
| ハッシュツリー | `HashTree`、`ReducedHashtree`、`Digest` | ハッシュの計算だけを行う。ASN.1 もタイムスタンプも扱わない |
| データ構造 | `Record`、`Chain`、`ArchiveTimeStamp`、`TimeStampToken` | ASN.1 DER の読み書き。元のバイト列を保持する |
| 操作 | `Generator`、`TimestampRenewal`、`HashTreeRenewal`、`Record#verify` | 生成、2 種類の更新、検証 |

### 3.2 名前空間

- gem 名は `evidence_record`、モジュールは `EvidenceRecord` とする（gem 名と定数名の慣例に合わせる）
- RFC の `EvidenceRecord` 型を表すクラスは `EvidenceRecord::Record` とする。モジュール名と同じ名前のクラスは作れないため
- `ERS` モジュールにして `ERS::EvidenceRecord` とする案（RFC の型名とそろう）も検討したが、gem 名との対応を優先した

### 3.3 生成

```ruby
gen = EvidenceRecord::Generator.new(digest_algorithm: :sha256)
gen.add("doc-a")                                   # => 0（追加順の位置）
gen.add(EvidenceRecord::DataGroup.new(["meta.xml の中身", "body.pdf の中身"])) # => 1

req = gen.timestamp_request(nonce: SecureRandom.random_number(2**64), cert_requested: true)
# => OpenSSL::Timestamp::Request（利用者が TSA に送る）
res = post_to_tsa(req.to_der)   # TSA の応答のバイト列（String）

records = gen.build(res)   # => [Record, Record]（add した順）
# OpenSSL::Timestamp::Response を渡してもよい（6 章）
records[0].to_der
```

- TSA とのやりとりを 2 段階にしたのは、Bouncy Castle と同じ理由による。HTTP クライアント、認証、リトライなどは TSA ごとに違い、gem が抱えると範囲が広がりすぎる。ct_merkle の「外部とのやりとりは利用者に任せる」方針とも合う
- `build` では、応答の状態（granted / grantedWithMods かどうか）、messageImprint のアルゴリズム、値（ハッシュツリーのルート）を確認し、一致しなければ `TimestampResponseError` にする。拒否された場合は、TSA が返した status と statusString をメッセージに含める
  - `timestamp_request` に `nonce:` / `policy_id:` を渡した場合は、応答のトークンの値が同じことも確認する（RFC 3161 §2.4.2 で要求者が確認すべきとされている）
  - トークンの署名は確認しない（信頼する証明書を `Generator` は知らないため）。必要なら、できた `Record` を `verify` する
- `timestamp_request` の `cert_requested:` は既定で `true`。後で検証するときに TSA の証明書が必要になるため
- データは `add` の時点でハッシュし、データそのものは保持しない
- `timestamp_request` または `build` の後に `add` するのは `EvidenceRecord::Error` にする（Bouncy Castle には「要求を作った後にデータを追加すると不整合になる」ことを確かめるテストがある）。データを 1 つも追加せずに `timestamp_request` / `build` を呼んだ場合も同じ
- **ER は `build` のときに全部の葉について一度に作る**。ハッシュツリーは保存しないので、後から特定の葉の ER を作り直すことはできない
  - ER を後から作れるようにするには、ct_merkle の `Tree` と同様にハッシュツリーの保存が必要になる。ct_merkle も v1 では `Tree` を保存できないので、それにそろえてシンプルにした
  - 規模が大きい場合は、ツリーとタイムスタンプを保存し、要求されたときに ER を作るほうが有利な面もある。全 ER がタイムスタンプ（BSI のテストデータで 1 つ約 5〜6KB）を複製して持つことや、タイムスタンプ更新で全 ER に書き込む必要がないためである。後から追加できるように、`HashTree` は `Generator` から切り離して公開しておく

### 3.4 タイムスタンプ更新

```ruby
renewal = record.timestamp_renewal          # => TimestampRenewal
req     = renewal.timestamp_request(nonce: ...)
record2 = renewal.build(res)               # => 新しい Record（最後の Chain に ATS を 1 つ追加）
```

- 新しい ATS が対象とするのは、**最後の Chain の全 ATS の timeStamp**（DER）を 1 つのデータオブジェクトグループにしたもの（Bouncy Castle と同じ）
  - RFC 4998 が求めているのは「直前の ATS の timeStamp を含むこと」だけだが、Bouncy Castle の検証（`ERSEvidenceRecord#validate`）は、最後の ATS が同じ Chain の前の ATS の timeStamp をすべて含むことを確認する。Bouncy Castle で検証できるように、こちらに合わせる
  - RFC の検証手順（直前の timeStamp が含まれていること）でも問題なく検証できる
- 対象の timeStamp が 1 つだけ（最初の更新）のときは、そのハッシュ値をそのまま imprint にし、`reducedHashtree` と `digestAlgorithm` は省く。2 つ以上のときは、それらのハッシュ値だけを並べた 1 段の `reducedHashtree` と `digestAlgorithm` をつける（どちらも Bouncy Castle の `ERSArchiveTimeStampGenerator` と同じ）
- ハッシュアルゴリズムは最後の Chain のものを使う。アルゴリズムを変えたいときはハッシュツリー更新を使う（3.5）
- データは不要で、更新の前に ER を検証しない。最後の Chain が空、または Chain 内でアルゴリズムが混在している場合は `MalformedRecordError`、対応していないアルゴリズムなら `UnsupportedAlgorithmError` にする
- `build` は、生成（3.3）と同じ応答の確認に加えて、新しい TST の genTime が最後の TST の genTime より前なら `TimestampResponseError` にする（そのまま追加すると検証で必ず失敗するため）
- 同じツリーから作った ER は timeStamp が同じなので、1 つの TSA 応答を `related_to?` の ER どうしで使い回せる。それぞれの ER で `timestamp_renewal` を作り、同じ応答を `build` に渡す（nonce などの確認は、`timestamp_request` を呼んだ更新でだけ行われる）。同じ応答で更新を続ければ、以降の更新も使い回せる
- v1 では、複数の ER をまとめて更新する API は提供しない（11 章）

### 3.5 ハッシュツリー更新

```ruby
renewal = record.hash_tree_renewal(data: "doc-a", digest_algorithm: :sha512) # => HashTreeRenewal
req     = renewal.timestamp_request(nonce: ...)
record2 = renewal.build(res)               # => 新しい Record（新しい Chain を追加）
```

- 新しいハッシュツリーの葉は `H(H(d) ‖ ha)` とする
  - `H` は新しいアルゴリズム、`d` はデータオブジェクト、`ha` はそれまでの ATS Sequence の DER のハッシュ
  - **生成では、連結はソートせず、この固定順にする**
  - **検証では、固定順とソート順の両方を受け付ける**（5.1）
  - 理由: この連結順は RFC 4998 の中で記述が食い違っている
    - §5.2 手順 4（本文）は `h(i)' = H(h(i) + ha(i))` で、固定順
    - §5.2 Figure 4 の説明は `h1' = H( binary sorted and concatenated (H(d1), ha(1)))` で、ソート順
    - [Errata 7411](https://www.rfc-editor.org/errata/rfc4998)（2023 年、状態は Reported で未確定）は、本文をソート順に直すべきとしている
  - 実際の実装は固定順である。BSI のテストデータ（ERS-Testtool `2Chains3ATS`）は固定順でだけ一致し、ソート順では一致しないことを確認した（この例では `H(d) > ha` なので、2 つの順序の結果が異なり区別できる）。Bouncy Castle（`ERSUtil.concatPreviousHashes`）も固定順
  - 生成は、相手の実装で検証できることを優先して固定順にする。検証は、Figure 4 や Errata に従った実装が作った ER も読めるように、両方を試す。どちらか一方で一致すればよいとしても、攻撃者は 2 通りのどちらかについて衝突を作る必要があり、安全性はほとんど変わらない
  - データオブジェクトグループの場合は、メンバーごとに `H(H(d_i) ‖ ha)` を計算する（Bouncy Castle と同じ）
- 渡されたデータが今の ER で検証できない場合は、更新を始める前にエラーにする（間違ったデータで更新すると、以降の検証がすべて失敗するため。Bouncy Castle と同じ）
- 新しいアルゴリズムは、ER の `digestAlgorithms` にも追加する

### 3.6 検証

```ruby
record = EvidenceRecord::Record.from_der(der)

validator = EvidenceRecord::TimestampValidator::OpenSSL.new(store: x509_store)
record.verify(data: "doc-a", timestamp_validator: validator)    # => true / false
record.verify!(data: "doc-a", timestamp_validator: validator)   # 失敗時は例外

# データ本体の代わりに、計算済みのハッシュで検証する（3.7）
pre = EvidenceRecord::PrehashedData.new(sha256: digest256, sha512: digest512)
record.verify(data: pre, timestamp_validator: validator)

# ハッシュの連鎖だけを検証する（タイムスタンプの署名は確認しない）
record.verify_hashes(data: "doc-a")

record.proven_time   # => Time（最初の ATS の genTime）
```

- **2 段階に分ける**: 「ハッシュの連鎖の検証」と「タイムスタンプ自体の正当性」を分ける（5 章）。Bouncy Castle の `validatePresent` と `validate` に相当する
- **`timestamp_validator:` は必須にする**: 省略できると、署名を確認しない検証が気づかれずに使われるおそれがある。ハッシュの連鎖だけを確認したい場合は `verify_hashes` を明示的に使う
- **`at:`**: 検証の基準時刻。既定は現在時刻。最後のタイムスタンプは、この時刻で有効かを確認する
- `verify_hashes` にも、例外を投げる `verify_hashes!` を用意する
- 対応していないハッシュアルゴリズム（SHA-1 など）の ER は、`verify` でも `false` ではなく `UnsupportedAlgorithmError` にする。「不正」ではなく「このライブラリでは判定できない」ため
- `PrehashedData` に、検証に必要なアルゴリズムのハッシュがない場合は `ArgumentError` にする（呼び出し方の誤り）

### 3.7 データの指定

| 渡すもの | 扱い |
|---|---|
| `String` | バイト列として扱う（パスとしては扱わない） |
| `PrehashedData` | 外部で計算済みのハッシュ値（3.7.1） |
| `DataGroup` | データオブジェクトグループ。メンバーは上の 2 種類 |

- データを受け取る引数（`Generator#add`、`verify` / `verify_hashes` の `data:`、`hash_tree_renewal` の `data:`）は、すべて上の表のどれでも受け付ける
- **IO や Pathname は受け付けない**（ct_merkle と同じく、データは String で受け取る）
  - 大きなファイルは、利用者がハッシュを計算して `PrehashedData` で渡す（例: `OpenSSL::Digest.new("SHA256").file(path).digest`）。ER の葉はただの `H(data)` なので、ct_merkle（`H(0x00 ‖ data)`）より計算は簡単である
  - 当初は IO と Pathname も受け付ける案だった（Bouncy Castle の `ERSInputStreamData` / `ERSFileData` に相当）。しかし、受け付ける理由は大きなファイルを扱う手間を省くことだけで、`PrehashedData` で代わりになる。IO は一度読むと位置を戻す必要があり、戻せない IO ではエラーにするしかないなど扱いが複雑になるため、やめた。テストデータ（BSI、Bouncy Castle）も小さく、`File.binread` で足りる
- String をパスとして扱わないのは、ct_merkle で hex / base64 を自動判別しなかったのと同じ理由。取り違えたときに気づけなくなる
- String はエンコーディングに関係なくバイト列として扱う（ct_merkle と同じ）
- ハッシュはアルゴリズムごとにキャッシュする（ハッシュツリー更新や検証では、同じデータを複数のアルゴリズムでハッシュするため。Bouncy Castle の `ERSCachingData` と同じ）
- グループの入れ子（Bouncy Castle の `ERSDirectoryDataGroup`）は v1 では扱わない

#### 3.7.1 計算済みのハッシュ（`PrehashedData`）

ct_merkle の `append_leaf_hash` に相当する。データ本体の代わりに、データオブジェクトのハッシュ値を渡す。

```ruby
pre = EvidenceRecord::PrehashedData.new(sha256: d256, sha512: d512)

gen.add(pre)                                                      # 生成（Generator のアルゴリズムのハッシュを使う）
record.verify(data: pre, timestamp_validator: validator)          # 検証（全 Chain のアルゴリズムのハッシュを使う）
record.hash_tree_renewal(data: pre, digest_algorithm: :sha512)    # 更新（今と新しいアルゴリズムの両方を使う）
gen.add(EvidenceRecord::DataGroup.new([pre_meta, pre_body]))      # グループのメンバーにもできる
```

- 想定する用途
  - データ本体を手元に置かない（利用者の端末でハッシュだけを計算して送る、など）
  - 保存システムがハッシュを記録済みで、データを読み直したくない
  - テスト（TR-ESOR C.2 の ER は、ハッシュしか分からないデータグループを対象にしている）
- ct_merkle と違い、`Digest` を 1 つ渡す形にはしない。処理によって必要なアルゴリズムが違い、1 つの処理で複数のアルゴリズムのハッシュが必要になることもあるため（ハッシュツリー更新、複数の Chain を持つ ER の検証）。そこで、アルゴリズムからハッシュ値への対応を持つオブジェクトにした
  - 初版の草案では検証だけに `verify(hashes: {...})` を用意していたが、生成と更新でも同じものを使えるように、データと同じ場所に渡すこのオブジェクトにまとめた
- ハッシュ値は `Digest` またはバイト列の String で受け取る（ct_merkle と同じ）
- 処理に必要なアルゴリズムのハッシュが入っていない場合と、ハッシュの長さがアルゴリズムの出力長と違う場合は、`ArgumentError` にする
- **複数のハッシュが同じデータから計算されたものかは、ライブラリでは確認できない**。ハッシュツリー更新で、今のアルゴリズムのハッシュ（更新前の検証に使う）と新しいアルゴリズムのハッシュ（新しい Chain に使う）が別のデータのものだと、更新前の検証には通るのに、新しい Chain が別のデータを指す壊れた ER ができる。これは利用者の責任とし、リファレンスに明記する

### 3.8 その他の API

- `Record#related_to?(other)`: 最初の ATS の timeStamp が同じか（同じツリーから作られたか）。更新の応答を使い回すときに使う
- `Record#chains` / `Chain#archive_timestamps` / `ArchiveTimeStamp#reduced_hashtree` / `ArchiveTimeStamp#timestamp`: 構造を読むための属性
- `TimeStampToken#gen_time` / `#message_imprint` / `#hash_algorithm` / `#serial_number` / `#policy_id` / `#nonce` / `#certificates` / `#to_der`
- 対応していないアルゴリズムの ER も読めるように、アルゴリズムは OID の文字列でも取得できる（`Record#digest_algorithm_oids`、`ArchiveTimeStamp#digest_algorithm_oid`、`TimeStampToken#hash_algorithm_oid`）。`DigestAlgorithm` を返すメソッドは、対応していない OID なら `UnsupportedAlgorithmError` にする
- `Record#crypto_infos` / `#encryption_info` / `ArchiveTimeStamp#attributes` は、読み込んだ DER（タグを含む）をそのまま返す（7.3）

### 3.9 例外

```
EvidenceRecord::Error < StandardError
├── ParseError                 DER として不正、または RFC 4998 の構造に合わない
├── UnsupportedAlgorithmError  対応していないハッシュアルゴリズム
├── TimestampResponseError     TSA の応答が不正（拒否、imprint の不一致など）
└── VerificationError          verify! の失敗
    ├── MalformedRecordError   構造が不正（空の Chain、Chain 内でアルゴリズムが混在など）
    ├── HashMismatchError      データが含まれていない、ルートが imprint と一致しない
    └── TimestampInvalidError  timestamp_validator が不正と判定した
```

- 呼び出し方そのものの誤り（引数の型など）は `ArgumentError` とし、`verify` でも `false` にはしない（ct_merkle と同じ）
- `HashMismatchError` と `TimestampInvalidError` を分けたのは、前者は「データの取り違え・改ざん」、後者は「信頼の設定・証明書の期限切れ」と、原因と対処が大きく違うため
- `VerificationError` は、失敗した場所を `chain_index` / `ats_index` 属性で持つ（場所が特定できない構造の不正では `nil`）。どこで失敗したかを、メッセージを解析せずに取得できるようにするため
- 検証の詳細（各 ATS の genTime、アルゴリズムなど）をまとめた結果オブジェクトは返さない
  - 必要な情報は `Record#chains` などの属性（3.8）から取得できる。次の更新時期の判断に使う、最後の TST の genTime や TSA 証明書も同様
  - 公開 API が増えると、互換性を保つ負担が増える
  - `verify` が結果オブジェクトを返すと、`if record.verify(...)` が失敗しても真になり危険。作るとしても別のメソッドにする必要があり、後から追加しても既存の API を壊さない

## 4. ハッシュツリー

### 4.1 計算の定義（RFC 4998 §4.2 / §4.3）

- データオブジェクトのハッシュ: `H(d)`
- グループのハッシュ: メンバーのハッシュをバイナリ昇順にソートして連結し、`H(...)`
- PartialHashtree の値が 1 つだけの場合は、**ハッシュせずにその値をそのまま使う**。BSI のテストデータ（`testRenewal.ers`）と Bouncy Castle で確認した。RFC の本文からは読み取りにくい点なので、明示しておく
- 2 段目以降: 前の段で計算したハッシュと、その段の PartialHashtree の全値をまとめてソートして連結し、`H(...)`

### 4.2 生成するツリーの形

- 2 分木にする。**葉をハッシュ値の昇順に並べ替えてから、隣どうしを組にする**（Bouncy Castle の `BinaryTreeRootCalculator` と同じ）。奇数個で余った 1 つは、ハッシュせずにそのまま上の段に上げる
  - 葉のハッシュ値は、データオブジェクトなら `H(d)`、グループならメンバーのハッシュをソートして連結した値のハッシュ
  - 組にした 2 つをつなげる順番は、RFC のとおりハッシュ値の昇順とする（RFC 4998 §4.2 手順 4 の「sort each group in binary ascending order」。どの実装でも同じ）
  - どの葉どうしを組にするかは、RFC は決めていない（「place them in groups」とあるだけで、子の数をそろえるために任意のデータを足してもよいとしている）。組み方によってルートの値は変わるが、検証は ER の中の経路だけを使い、ツリーの組み方に依存しないので、どの組み方で作った ER も正しく検証できる
  - それでも Bouncy Castle と同じ組み方にしたのは、同じ入力から同じルート（同じタイムスタンプ要求）になり、次のことができるため
    - Bouncy Castle のテスト（`ERSTest`）の期待値を、そのままテストベクタとして使える。Bouncy Castle は MIT ライセンスで、入力も短い文字列なので、BSI のデータのようなライセンスの問題がない
    - 相互運用テストで、ルートの値を直接比べられる
  - 当初は追加順に組む案だった。`testBasicBuild`（葉 3 つ）の期待値 `98fbf91c…` は、並べ替えてから組んだ場合だけ一致することを確認した
  - ツリーの中の葉の位置は追加順でなくなるが、`Generator#build` が返す ER は追加順にそろえる（Bouncy Castle も同じ）。同じハッシュ値の葉が複数ある場合も、それぞれに ER を作る
- 生成するツリーの形を差し替える仕組み（Bouncy Castle の `ERSRootNodeCalculator`）は v1 では用意しない。検証は形に依存しないので、差し替えの必要性が低い
- データオブジェクトが 1 つだけで、グループでもない場合は、reducedHashtree を省略し、タイムスタンプが `H(d)` を直接対象とする（RFC 4998 §4.2、Bouncy Castle と同じ）

### 4.3 `Digest`

- ct_merkle の `CTMerkle::Digest` と同じ設計の値オブジェクト（バイト列だけを持つ。`to_hex` / `to_base64` / `from_hex` / `from_base64`、比較の規則も同じ）
- アルゴリズムは持たせない。PartialHashtree の値は ASN.1 上でもただの OCTET STRING で、アルゴリズムは ATS が持っているため
- ct_merkle には依存せず、コピーする（ct_merkle を共通部品として依存させるほどの量ではない）

### 4.4 ハッシュアルゴリズム

- シンボル（`:sha256` / `:sha384` / `:sha512`）で指定し、内部で OID との対応表を持つ
- 生成でも検証でも、対応するのは上の 3 つだけとする
  - SHA-1 は受け付けない。古い ER を読むためには必要になりうるが、すでに安全でないアルゴリズムで、v1 で対応する必要性は低い
  - SHA-3 系にも対応しない。ERS で使われている例が少なく、必要になってから対応表に追加すれば足りる
- 対応表にない OID（SHA-1、SHA-3 を含む）は、読み込みはできるが、検証、更新、生成では `UnsupportedAlgorithmError` にする

## 5. 検証

### 5.1 手順

1. **構造**: Chain が 1 つ以上、各 Chain に ATS が 1 つ以上ある。Chain 内の ATS はすべて同じハッシュアルゴリズム
2. **各 Chain の最初の ATS**: データのハッシュ（2 つ目以降の Chain では `H(H(d) ‖ ha)`。含まれなければ、ソート順で連結した値も試す。3.5）が最初の PartialHashtree に含まれ、そこから計算したルートが TST の messageImprint と一致する。アルゴリズムも一致する
3. **Chain 内の 2 つ目以降の ATS**: 直前の ATS の timeStamp の DER のハッシュが最初の PartialHashtree に含まれ、ルートが messageImprint と一致する
4. **時刻**: genTime が前の ATS 以上で、最後の genTime が `at:` 以前
5. **タイムスタンプの正当性**: 各 TST について `timestamp_validator.call(token, at: 基準時刻)` を呼ぶ。基準時刻は、その TST を対象に含む次の TST の genTime とし、最後の TST だけは `at:` とする

補足:

- 手順 1 では、ATS の `digestAlgorithm` があれば TST の messageImprint のアルゴリズムと一致すること（RFC 4998 §5.3）、reducedHashtree のハッシュの長さがアルゴリズムに合うことも確認する
- 「含まれる」は、データ（グループならメンバー全員）のハッシュが最初の PartialHashtree の値の中にあること。最初の PartialHashtree にほかの値（兄弟ノード）があってもよい。グループのメンバー 1 つだけを渡しても、そのデータの存在は証明できるので成功する
- reducedHashtree がない ATS は、データのハッシュ（グループならメンバーのハッシュをソートして連結したもののハッシュ）が messageImprint と直接一致すればよい
- 例外の使い分け: 手順 1 と手順 4 の genTime の順序は `MalformedRecordError`、手順 2・3 は `HashMismatchError`、手順 4 の `at:` との比較と手順 5 は `TimestampInvalidError`

### 5.2 Bouncy Castle との違い

- **任意の形のツリーを検証できる**: Bouncy Castle（`BinaryTreeRootCalculator#recoverRootHash`）は、2 段目以降の PartialHashtree に値が複数あると、それを先にまとめてハッシュしてから前の段の結果と組むので、RFC の手順と結果が違う。BSI のテストデータ TR-ESOR C.2 `ER_OK_SEQ`（2-3-1 の形）では、RFC の手順でだけ検証に通ることを確認した
- **すべての Chain をデータと照合する**: Bouncy Castle がデータと照合するのは最後の Chain の最初の ATS だけで、古い Chain は Sequence のハッシュを通じて間接的につながっているだけ。このライブラリでは、各 Chain の最初の ATS をそれぞれのアルゴリズムで照合する
- **すべての TST を validator に渡す**: Bouncy Castle の `validate` が署名を確認するのは最後の ATS だけ

### 5.3 タイムスタンプの検証器

- 検証器は `call(token, at:)` を持つオブジェクトとする。有効なら真を返す。不正なら `TimestampInvalidError` を投げるか、偽（`false` / `nil`）を返す
  - 偽を返した場合も不正として扱う。真を返し忘れた検証器が、気づかれずにすべてを通してしまわないようにするため（fail closed）
  - それ以外の例外は捕まえない。検証器のバグ（`NoMethodError` など）が「不正」に化けて隠れないようにするため
  - `verify!` は、検証器が投げた `TimestampInvalidError` を `chain_index` / `ats_index` を付けて投げ直す（元の例外は `cause` に入る）
- 同梱する `TimestampValidator::OpenSSL` は、`OpenSSL::X509::Store` を受け取り、署名と証明書チェーンを `at:` の時刻で検証する
  - 中身は `OpenSSL::Timestamp::Response#verify`。署名、ESS signing certificate による署名者証明書の確認、証明書の用途（timeStamping）、信頼できる証明書までのチェーンを確認する
  - `crls` を取り除いたトークンを TimeStampResp に包んで渡す（7.2）。照合用の Request はトークン自身の messageImprint と nonce から作る（messageImprint とハッシュの連鎖の照合は手順 2・3 で済んでいる）
  - 呼び出しのたびに Store の検証時刻（`Store#time=`）を書き換える。Ruby の openssl には検証時刻を Store を変えずに渡す方法がないため。ドキュメントに、この検証器専用の Store を渡すよう書く
- 失効の確認（CRL / OCSP）や、アルゴリズムが危殆化していないかの判定は v1 では行わない。必要な利用者は、独自の検証器を渡す。ドキュメントには、同梱の検証器でできることとできないことを明記する

## 6. TSA とのやりとり

- 要求は `OpenSSL::Timestamp::Request` で作る。`nonce` / `cert_requested` / `policy_id` は呼び出し側が指定できる
- 応答は、TimeStampResp のバイト列（String）か `OpenSSL::Timestamp::Response` で受け取る（`build` など、TSA の応答を受け取るメソッドすべて）
  - String を基本とする。Ruby の `OpenSSL::Timestamp::Response` は、`crls` に OCSP 応答を含む応答を解析できず、そうした TSA では `Response` オブジェクトを作れないため（7.2）
  - `OpenSSL::Timestamp::Response` を渡された場合は、`to_der` で得たバイト列を同じように扱う
  - 応答の解析（status の確認、トークンの取り出し）はライブラリが自前の DER リーダーで行う
- **長さの書き方が BER の応答も受け付ける**（7.2）
  - 不定長と、最短でない長さを定長・最短の形に直してから読む。直すのは長さの書き方だけで、中身のバイト列は変えない
  - ER に入るのは、直した後のトークン（DER）。応答の外側（status など）は ER に残らない
  - 長さを直しても DER にならない応答（constructed な OCTET STRING、SET の順序、BOOLEAN の値など）は `TimestampResponseError` にする。それらを直すと中身が変わり、トークンに含まれる証明書の署名などを壊すおそれがあるため。Bouncy Castle はトークン全体を DER に書き直すが、実際に見つかった例（BSI のテストデータの TSA）は外側の不定長だけだったので、必要な範囲に絞る
  - `Record.from_der` は、これまでどおり DER だけを受け付ける。BER を受け付けるのは TSA の応答という入口だけ
- テストでは `OpenSSL::Timestamp::Factory` でローカルの TSA を作る

## 7. ASN.1 とバイト列

### 7.1 元のバイト列の保持

- ハッシュの対象になるのは、ATS の timeStamp（タイムスタンプ更新）と ATS Sequence（ハッシュツリー更新）の DER。解析したものを再エンコードすると、元のバイト列と一致しない場合がある
- データ構造クラスは、読み込んだときの DER をそのまま保持し、`to_der` はそれを返す
- 読み込み時に ER 全体が DER であることを確認し、DER でなければ `ParseError` にする。書き出す ER も常に DER にする
  - RFC 4998 が DER を明記しているのは、ハッシュツリー更新で `ha` を計算するときの ArchiveTimeStampChain だけである（§5.2 "The ArchiveTimeStampChains used are DER encoded"）
  - timeStamp は、RFC には明記がないが、次のタイムスタンプ更新でハッシュされる。Bouncy Castle は DER に再エンコードしてからハッシュするので、BER のままでは結果が食い違う
  - それ以外のフィールド（version、digestAlgorithms、cryptoInfos、encryptionInfo）はハッシュの対象にならず、RFC 上は BER でも差し支えない。それでも、このライブラリの方針として ER 全体を DER に限る。これまでに確認した実装（BSI の ERS-Testtool、Bouncy Castle）が出力する ER はすべて DER であり、一部だけ BER を許すと受け付ける範囲の判断が複雑になるため
- DER の確認と、各要素の元のバイト列の取り出しには、自前の小さな DER リーダー（`EvidenceRecord::DER`、内部用）を使う
  - 当初は「`OpenSSL::ASN1` で解析して再エンコードしたものが元と一致するか」で確認する予定だったが、次の理由でやめた
    - `OpenSSL::ASN1` は不定長や constructed な OCTET STRING をそのまま再エンコードするので、BER を見逃す
    - GeneralizedTime の小数秒を捨てるので、正しい DER が一致しなくなる。BSI のテストデータの genTime にも小数秒がある（`20170210140936.5Z` など）
  - 確認する内容: 長さが最短形式であること、不定長でないこと、プリミティブ型が constructed でないこと、BOOLEAN / INTEGER / NULL / BIT STRING / OID の値の符号化、UNIVERSAL の SET の要素がソートされていること、時刻の形式、末尾に余分なデータがないこと
  - 暗黙タグ付きの SET（CMS の `certificates` など）の並び順は、型の情報がないため確認しない
- genTime も自前で読み、小数秒を保持する

### 7.2 Ruby の OpenSSL で TST を読めない問題

- 実際の TSA が発行するタイムスタンプには、CMS の `crls` フィールドに OCSP 応答（`OtherRevocationInfoFormat`）が埋め込まれていることがある。BSI のテストデータはすべてそうなっている
- Ruby の `OpenSSL::PKCS7` / `OpenSSL::Timestamp` は PKCS#7 v1.5 の構造しか解析できず、これを読めない。Ruby の openssl には CMS のバインディングもない
- 対策:
  - TSTInfo（genTime、messageImprint など）は `OpenSSL::ASN1` で直接読む
  - 署名の検証では、`crls` を取り除いたコピーを作って `OpenSSL::Timestamp::Response#verify` に渡す。`crls` は署名の対象外なので、取り除いても検証結果は変わらない。BSI のテストデータ（RSASSA-PSS の証明書チェーン）で動作を確認した
  - 取り除いたコピーは検証のためだけに使い、ハッシュの計算には使わない（7.1）

- **TSA が返すタイムスタンプが BER のことがある**: BSI のテストデータにある、TSA から得たタイムスタンプトークン（`2Chains3ATS/*.tsr`）は、ContentInfo の外側が不定長で符号化されている。同じテストデータの ER には、これを定長に直したもの（DER）が入っていることを確認した。署名の対象（signedAttrs と eContent の中身）は変わらないので、ER に入れるときに DER に直す必要がある（生成と更新で対応する。6 章）

### 7.3 読み込むが生成しないフィールド

- `cryptoInfos`、`encryptionInfo`、ATS の `attributes` は、読み込んで保持し、そのまま書き出す。値を解釈したり、生成したりはしない（v1 の範囲外）

## 8. 実装の方針

- 依存は `openssl`（`OpenSSL::ASN1`、`OpenSSL::Timestamp`、`OpenSSL::X509`）と `digest`。どちらも標準ライブラリ
- 対応する Ruby は 3.4 以降。RBS はつけない
  - Ruby 3.3 に同梱の openssl gem（3.2 系）では、`OpenSSL::X509::Store#time=` が `OpenSSL::Timestamp::Response#verify` に効かず、TST の証明書を現在時刻で検証してしまう（openssl gem 3.3.0 で修正）。`TimestampValidator::OpenSSL`（5.3）が正しく動かないため、3.3 は対象外にする（依存を標準ライブラリだけにする方針を保つため、openssl gem の新しい版を依存に加えることはしない）
- 値オブジェクトは frozen にする。データ構造クラス（`Record` など）は、`Data` ではなく普通のクラスで実装する。`Data#with` などでフィールドを変えると、保持している DER と中身が食い違うため。外から `new` は呼べないようにし、`from_der` だけを公開する（生成と更新では、内部用のメソッドで DER を組み立ててから `from_der` で読み直す）
- スレッドセーフではない（`Generator` と各更新オブジェクトは状態を持つ）

## 9. テストの方針

- **RFC の定義をそのまま書いた素朴な実装**と照合する（ct_merkle と同じ）
- **ローカルの TSA**（`OpenSSL::Timestamp::Factory`）で、生成 → タイムスタンプ更新 → ハッシュツリー更新 → 検証を一通り試す
- **Bouncy Castle のテストの期待値**と照合する（4.2）
  - [bc-java](https://github.com/bcgit/bc-java) の `pkix/src/test/java/org/bouncycastle/tsp/test/ERSTest.java` にある、入力（`"This is H1"` など）とルートの期待値を使う
  - 確認済み: `testBasicBuild`（`98fbf91c…`）、`test4NodeBuild`（`d82fea0e…`）。`testBuildMultiGroups`（`06836dfd…`）、`testBuildMulti`（`b7efd5e7…`）なども、実装時に照合する
  - 期待値は数行の定数なので、出典（ファイル名とテスト名）を書いてテストコードに直接書く
- **BSI のテストデータ**を使う
  - 取得元: [bcgit/bc-test-data](https://github.com/bcgit/bc-test-data) の `tsp/20170316_Testdaten/`。コミット `554cb4fab4dd9ace4a4ca4e6574364440b8c8eef` に固定する
  - **リポジトリには同梱しない**。bc-test-data にライセンスの記載がなく、出典（BSI）のライセンスも確認できなかったため。rake タスク（例: `rake test:fetch_vectors`）でテスト時に取得し、データがなければそのテストはスキップする
  - 期待する結果:

    | ファイル | 期待 | 確認すること |
    |---|---|---|
    | ERS-Testtool `1Chain1ATS` / `1Chain2ATS` / `2Chains3ATS` | 成功 | 初回、タイムスタンプ更新、ハッシュツリー更新（`BIN.bin` で検証） |
    | ERS-Testtool `1Chain2ATS/testRenewal.ers` | 成功 | 値が 1 つの PartialHashtree（Bouncy Castle が生成） |
    | TR-ESOR C.2 `ER_OK_*` | 成功 | n 分木（2-3-1）。データ本体がないので、`PrehashedData` で検証する |
    | TR-ESOR C.2 `ER_NOK_*` | 失敗 | 書き換えられたハッシュを検出できるか |

  - 証明書はすでに期限が切れているので、タイムスタンプの検証は genTime の時刻で行う
  - 信頼する証明書には、トークンに含まれている自己署名の証明書（BSI のテスト用 TSA のルート）を使う。`2Chains3ATS` は 2 つ目の Chain で TSA が変わり、ルートも別になる
  - 実装して確認した結果:
    - ERS-Testtool の 4 つは、`BIN.bin` で署名の検証まで含めて成功する
    - TR-ESOR C.2 の ER は `BIN.bin` ではなく、テストデータに含まれない 2 つの文書のグループが対象だった。最初の PartialHashtree の値から `PrehashedData` のグループを作ると、`ER_OK_INIT` / `ER_OK_CHAIN` は成功し、`ER_NOK_INIT` は Chain 0 の ATS 0、`ER_NOK_CHAIN` は Chain 0 の ATS 1 で `HashMismatchError` になる
    - `ER_OK_SEQ` / `ER_NOK_SEQ` の 2 つ目の Chain は SHA-384 で、文書の SHA-384 ハッシュがないため最後までは検証できない（n 分木の部分は、ルートが messageImprint と一致することをハッシュツリーのテストで確認している）
- **Bouncy Castle との相互運用テスト**を CI に入れる
  - 双方向で確認する
    - このライブラリで生成・更新した ER を、Bouncy Castle で検証する（`validatePresent` と `validate`）
    - Bouncy Castle で生成・更新した ER を、このライブラリで検証する
  - 確認したいことの例: タイムスタンプ更新の方針（3.4）、ハッシュツリー更新の連結順（3.5）、ルートの値（4.2）、DER の互換性
  - 構成（案）
    - Bouncy Castle を呼ぶ小さな Java プログラムを `interop/` に置く。Java の単一ファイル実行（`java ErsInterop.java`）で動かし、ビルドツールは使わない
    - Bouncy Castle の jar（bcprov / bcutil / bcpkix）は、Maven Central からバージョンを固定して取得する
    - TSA は両方ともテスト用の鍵で作る。ER と TSA の証明書をファイルでやりとりする
    - 通常のテストとは別の CI ジョブ（Java をセットアップする）にする。手元では Java がなければスキップし、docker compose のサービスとしても実行できるようにする

## 10. v1 で提供しないもの

| 機能 | 理由 |
|---|---|
| TSA との HTTP 通信 | 2 段階の API にしたため（3.3） |
| 複数の ER をまとめて更新する API | v1 では ER ごとの更新で十分と判断した。Bouncy Castle も ER ごと |
| `cryptoInfos` / `encryptionInfo` / `attributes` の生成と解釈 | 読み込んで保持するだけにする（7.3） |
| 失効の確認（CRL / OCSP）、アルゴリズムの危殆化の判定 | 検証器を差し替えて対応する（5.3） |
| XML 形式（RFC 6283） | ASN.1 形式を優先する |
| CMS への埋め込み（RFC 4998 §9） | 範囲外 |
| 多数の ER からの検索（Bouncy Castle の `ERSEvidenceRecordStore`） | 利用者の側で、リーフハッシュをキーにした索引を持てば足りる |
| ディレクトリをグループとして扱う機能 | グループの入れ子を扱わないため（3.7） |
| ハッシュツリーの保存と、後からの ER の生成 | ER は生成時に一度に作る（3.3）。ct_merkle の `Tree` の保存（`LeafStore`）と合わせて検討する |

## 11. 決定事項と未決事項

- [x] v1 の範囲
  - 生成、タイムスタンプ更新、ハッシュツリー更新、検証。作る順番は ハッシュツリー → ASN.1 → 検証 → 生成 → 更新
- [x] TSA との通信
  - 2 段階の API にし、HTTP クライアントは同梱しない（3.3）
- [x] 複数の ER をまとめて更新する API
  - v1 には入れない
- [x] BSI のテストデータの扱い
  - 同梱せず、テスト時に取得する（9 章）
- [x] 生成するツリーの組み方
  - 葉をハッシュ値の昇順に並べ替えてから組む（Bouncy Castle と同じ。4.2）。Bouncy Castle のテストの期待値をテストベクタとして使えるため
- [x] ハッシュツリー更新での `H(d)` と `ha` の連結順
  - 生成は固定順（`H(d) ‖ ha`）、検証は固定順とソート順の両方を受け付ける（3.5）。RFC 本文と Figure 4 が食い違っており、Errata 7411 が未確定のため。Errata が確定したら見直す
- [x] 外部で計算したハッシュ値を渡す方法を用意するか
  - 用意する。`PrehashedData` を、生成・検証・更新のすべてでデータの代わりに渡せるようにする（3.7.1）
- [x] ハッシュツリーを保存して、後から ER を作れるようにするか
  - v1 では行わない。ER は `build` のときに一度に作る（3.3）
- [x] モジュール名とクラス名
  - `EvidenceRecord` / `EvidenceRecord::Record`（3.2）
- [x] gem 名 `evidence_record` が rubygems.org で使われていないかの確認
  - 確認済み
- [x] 検証で SHA-1 を受け付けるか
  - 受け付けない（4.4）
- [x] SHA-3 系（`:sha3_256` など）に対応するか
  - 対応しない（4.4）
- [x] Bouncy Castle との相互運用テストを CI に入れるか
  - 入れる。双方向で確認する（9 章）
- [x] `Generator#build` などが受け取る TSA 応答の型（7.2）
  - TimeStampResp のバイト列（String）を基本とし、`OpenSSL::Timestamp::Response` も受け取る。長さの書き方が BER の応答は受け付けて、トークンを DER に直してから ER に入れる（6 章）
- [ ] タイムスタンプ更新で、最後の Chain の全 timeStamp を対象に含める方針（3.4）が、Bouncy Castle の実装と実際に互換か
  - 実装時に、相互運用テストで確認する
- [x] `verify` に結果オブジェクト（各 ATS の genTime、使ったアルゴリズムなど）を返す版を用意するか
  - 用意しない。失敗した場所は例外の属性で、詳細は `Record` の属性で取得する（3.9）
