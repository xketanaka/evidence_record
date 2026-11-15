# evidence_record API リファレンス

## 目次

- [共通仕様](#共通仕様)
- [EvidenceRecord](#evidencerecord)
- [EvidenceRecord::Generator](#evidencerecordgenerator)
- [EvidenceRecord::DataGroup](#evidencerecorddatagroup)
- [EvidenceRecord::PrehashedData](#evidencerecordprehasheddata)
- [EvidenceRecord::Record](#evidencerecordrecord)
- [EvidenceRecord::TimestampRenewal](#evidencerecordtimestamprenewal)
- [EvidenceRecord::HashTreeRenewal](#evidencerecordhashtreerenewal)
- [EvidenceRecord::TimestampValidator](#evidencerecordtimestampvalidator)
- [EvidenceRecord::TimestampValidator::OpenSSL](#evidencerecordtimestampvalidatoropenssl)
- [EvidenceRecord::Chain](#evidencerecordchain)
- [EvidenceRecord::ArchiveTimeStamp](#evidencerecordarchivetimestamp)
- [EvidenceRecord::TimeStampToken](#evidencerecordtimestamptoken)
- [EvidenceRecord::ReducedHashtree](#evidencerecordreducedhashtree)
- [EvidenceRecord::Digest](#evidencerecorddigest)
- [EvidenceRecord::DigestAlgorithm](#evidencerecorddigestalgorithm)
- [EvidenceRecord::HashTree](#evidencerecordhashtree)
- [例外](#例外)

## 共通仕様

### ハッシュアルゴリズム

対応するのは SHA-256、SHA-384、SHA-512 の 3 つ。アルゴリズムを受け取る引数（`digest_algorithm:` など）には、Symbol（`:sha256` / `:sha384` / `:sha512`）または `DigestAlgorithm` インスタンスを指定する

- それ以外の Symbol を渡すと `UnsupportedAlgorithmError`、Symbol 以外を渡すと `ArgumentError` になる
- 対応していないアルゴリズム(SHA-1 など)を使う Evidence Record も読み込めるが、検証、更新当は `UnsupportedAlgorithmError` になる

### データ

データを受け取る引数には、次のどれかを指定する

| 型 | 扱い |
|---|---|
| `String` | データオブジェクトのバイト列。エンコーディングに関係なくバイト列としてハッシュする |
| `PrehashedData` | 外部で計算済みの、データオブジェクトのハッシュ値 |
| `DataGroup` | データオブジェクトグループ。メンバーは String または `PrehashedData` |

### 引数のハッシュ値

ハッシュ値を受け取る引数には `EvidenceRecord::Digest` またはバイト列の String を指定する。hex や base64 の指定は不可

### 戻り値のハッシュ値

ハッシュ値を返すメソッドは `EvidenceRecord::Digest` を返す（ただし `DigestAlgorithm#digest` を除く）

### TSA との連携

このライブラリは TSA と通信しない。生成（`Generator`）と更新（`TimestampRenewal`、`HashTreeRenewal`）は、2 段階の API を持つ

1. `timestamp_request(...)` でタイムスタンプ要求（`OpenSSL::Timestamp::Request`）を作る。利用者がこれを TSA に送る
2. TSA の応答を `build(response)` に渡す

```ruby
req = gen.timestamp_request(nonce: SecureRandom.random_number(2**64))
res = post_to_tsa(req.to_der)   # 利用者が実装する
records = gen.build(res)
```

#### `timestamp_request(nonce: nil, cert_requested: true, policy_id: nil)` → `OpenSSL::Timestamp::Request`

タイムスタンプを付ける値に対するタイムスタンプ要求を返す。

- `nonce:`：Integer。指定すると要求に含め、`build` で応答のトークンの値と照合する
- `cert_requested:`：TSA に証明書をトークンに含めるよう求めるか。false にすると検証に TSA の証明書が別途必要になる
- `policy_id:`：TSA のポリシーの OID（String）。指定すると要求に含め `build` で応答のトークンの値と照合する

#### `build(response)`

TSA の応答からタイムスタンプトークンを取り出し、Evidence Record を作る

- `response`：TimeStampResp のバイト列または `OpenSSL::Timestamp::Response`
  - String を基本とする。Ruby の `OpenSSL::Timestamp::Response` は、CMS の crls に OCSP 応答を含む応答を解析できないため
  - `OpenSSL::Timestamp::Response` は `to_der` で得たバイト列として扱う
- 長さの書き方が BER（不定長、最短でない長さ）の応答は受け付け、DER に直したトークンを Evidence Record に入れる。長さ以外が DER でない応答は `TimestampResponseError`
- 次を確認し、満たさなければ `TimestampResponseError` を投げる
  - 応答の状態が granted または grantedWithMods（拒否された場合は、TSA が返した status と statusString をメッセージに含める）
  - タイムスタンプトークンがある
  - messageImprint のアルゴリズムと値が要求と同じ
  - `timestamp_request` に `nonce:` / `policy_id:` を指定した場合は、トークンの値が同じ
  - 更新の場合は、新しいタイムスタンプの genTime が Evidence Record の最後のタイムスタンプより前でない
- **タイムスタンプの署名は確認しない**。必要なら、作った Evidence Record を `Record#verify` で検証する
- `timestamp_request` を呼ばずに `build` を呼んでもよい（nonce と policy の照合は行わない）

### DER のデータ構造

`Record`、`Chain`、`ArchiveTimeStamp`、`TimeStampToken` は DER のバイト列を保持する値オブジェクト。イミュータブル。

- `from_der` で読み込むか、`Generator` や更新で作成する
- `from_der` は DER だけを受け付ける（BER は不可）。DER として不正な場合や、RFC 4998 / RFC 3161 の構造に合わない場合は `ParseError`
- `to_der` は読み込んだバイト列をそのまま返す
- `==` / `eql?` / `hash` は DER のバイト列で比較する

```
Record
└── chains: [Chain, ...]                         ArchiveTimeStampChain（同じハッシュアルゴリズム）
    └── archive_timestamps: [ArchiveTimeStamp, ...]
        ├── reduced_hashtree: ReducedHashtree / nil
        └── timestamp: TimeStampToken            RFC 3161 のタイムスタンプ
```

### スレッド安全性

`Generator`、`TimestampRenewal`、`HashTreeRenewal`、`HashTree` は状態を持ち、スレッドセーフではない。それ以外のオブジェクトは frozen である。

---

## EvidenceRecord

### `EvidenceRecord::VERSION`

gem のバージョン文字列。

---

## EvidenceRecord::Generator

多数のデータの Evidence Record を、1 つのタイムスタンプでまとめて作る。データのハッシュ値でハッシュツリーを作り、そのルートにタイムスタンプを付ける。スレッドセーフではない。

```ruby
gen = EvidenceRecord::Generator.new(digest_algorithm: :sha256)
gen.add("doc-a")                                              # => 0
gen.add(EvidenceRecord::DataGroup.new([meta_xml, body_pdf]))  # => 1
req = gen.timestamp_request(nonce: SecureRandom.random_number(2**64))
records = gen.build(post_to_tsa(req.to_der))                  # => [Record, Record]
```

データは `add` の中でハッシュし、データそのものは保持しない。

### `Generator.new(digest_algorithm: :sha256)`

ハッシュツリーのアルゴリズムを指定して作る。

### `#add(data)` → Integer

データオブジェクトまたはデータオブジェクトグループを追加し、その位置（0 から始まる追加順の番号）を返す。`build` が返す配列の位置と同じ。

- `data`：[データ](#データ)。`PrehashedData` には `Generator` のアルゴリズムのハッシュ値が必要で、なければ `ArgumentError`
- `timestamp_request` または `build` を呼んだ後は `EvidenceRecord::Error`（タイムスタンプは、その時点のハッシュツリーに対するものなので）

### `#size` → Integer

追加したデータオブジェクトとグループの数。

### `#digest_algorithm` → `DigestAlgorithm`

ハッシュツリーのアルゴリズム。

### `#root` → `Digest`

ハッシュツリーのルート。タイムスタンプを付ける値。

- データを 1 つも追加していなければ `EvidenceRecord::Error`

### `#timestamp_request(nonce: nil, cert_requested: true, policy_id: nil)` → `OpenSSL::Timestamp::Request`

`root` に対するタイムスタンプ要求を返す。[TSA とのやりとり](#tsa-とのやりとり)を参照。

- データを 1 つも追加していなければ `EvidenceRecord::Error`

### `#build(response)` → Array<`Record`>

TSA の応答から、追加したデータそれぞれの Evidence Record を作り、追加した順に返す。[TSA とのやりとり](#tsa-とのやりとり)を参照。

- データを 1 つも追加していなければ `EvidenceRecord::Error`

作る Evidence Record は、Chain が 1 つ、ArchiveTimeStamp が 1 つである。

- データオブジェクトを 1 つだけ追加した場合は、そのハッシュ値がそのまま messageImprint になり、ArchiveTimeStamp に reducedHashtree と digestAlgorithm を付けない
- それ以外の場合は、reducedHashtree と digestAlgorithm を付ける。ハッシュツリーの形は [HashTree](#evidencerecordhashtree) を参照

---

## EvidenceRecord::DataGroup

データオブジェクトグループ（RFC 4998 §4.2）。グループのメンバーは 1 つの Evidence Record で保護される。frozen である。

```ruby
group = EvidenceRecord::DataGroup.new([meta_xml, body_pdf])
gen.add(group)
record.verify(data: group, timestamp_validator: validator)
```

検証では、メンバーの一部だけを渡しても、渡したメンバーがすべてグループに含まれていれば成功する（そのデータの存在は証明できるため）。

### `DataGroup.new(members)`

- `members`：String または `PrehashedData` の配列
- 次の場合は `ArgumentError`
  - `members` が Array でない、または空
  - `DataGroup` を含む（入れ子は不可）
  - String / `PrehashedData` 以外の要素を含む

### インスタンスメソッド

| メソッド | 戻り値 | 説明 |
|---|---|---|
| `members` | Array | メンバーの配列（frozen） |
| `size` | Integer | メンバーの数 |

---

## EvidenceRecord::PrehashedData

データオブジェクトの、外部で計算済みのハッシュ値。データ本体の代わりに、生成、検証、更新のすべてで渡せる。frozen である。

```ruby
pre = EvidenceRecord::PrehashedData.new(
  sha256: OpenSSL::Digest.new("SHA256").file("large.bin").digest,
  sha512: OpenSSL::Digest.new("SHA512").file("large.bin").digest,
)
```

処理に必要なアルゴリズムのハッシュ値は次のとおり。足りなければ、その処理が `ArgumentError` を投げる。

| 処理 | 必要なハッシュ値 |
|---|---|
| `Generator#add` | `Generator` のアルゴリズム |
| `Record#verify` / `#verify_hashes` | Evidence Record の全 Chain のアルゴリズム |
| `Record#hash_tree_renewal` | Evidence Record の全 Chain のアルゴリズムと、新しいアルゴリズム |

**複数のハッシュ値が同じデータから計算されたものかは、ライブラリでは確認できない。** 例えばハッシュツリー更新で、今のアルゴリズムのハッシュ値（更新前の確認に使う）と新しいアルゴリズムのハッシュ値（新しい Chain に入る）が別のデータのものだと、更新はできても、以降の検証が失敗する Evidence Record ができる。同じデータから計算するのは利用者の責任である。

### `PrehashedData.new(**hashes)`

アルゴリズムごとのハッシュ値から作る。

- キー：アルゴリズムの Symbol。対応していないアルゴリズムなら `UnsupportedAlgorithmError`
- 値：[ハッシュ値](#引数のハッシュ値)。長さがアルゴリズムの出力長と違う場合は `ArgumentError`
- ハッシュ値が 1 つもなければ `ArgumentError`

### インスタンスメソッド

| メソッド | 戻り値 | 説明 |
|---|---|---|
| `algorithms` | Array<`DigestAlgorithm`> | ハッシュ値を持っているアルゴリズム |
| `[](algorithm)` | `Digest` / nil | `algorithm`（Symbol または `DigestAlgorithm`）のハッシュ値。持っていなければ `nil` |

---

## EvidenceRecord::Record

Evidence Record（RFC 4998 の `EvidenceRecord` 型）。[DER のデータ構造](#der-のデータ構造)の 1 つ。

```ruby
record = EvidenceRecord::Record.from_der(File.binread("doc-a.ers"))
record.verify(data: "doc-a", timestamp_validator: validator)   # => true / false
record.proven_time                                              # => Time
```

### `Record.from_der(der)` → `Record`

DER のバイト列から読み込む。

- DER として不正な場合、RFC 4998 の構造に合わない場合、version が 1 でない場合は `ParseError`

### 属性

| 属性 | 型 | 説明 |
|---|---|---|
| `version` | Integer | 常に `1` |
| `digest_algorithm_oids` | Array<String> | digestAlgorithms フィールド（Evidence Record で使われているアルゴリズムの一覧）の OID |
| `chains` | Array<`Chain`> | ArchiveTimeStampChain。古いものから順に並ぶ（frozen） |
| `crypto_infos` | String / nil | cryptoInfos フィールドの DER（`[0]` のタグを含む）。なければ `nil` |
| `encryption_info` | String / nil | encryptionInfo フィールドの DER（`[1]` のタグを含む）。なければ `nil` |

- digestAlgorithms フィールドは検証には使わない（検証では各 ArchiveTimeStamp のアルゴリズムを使う）
- cryptoInfos と encryptionInfo の中身は解釈しない。更新しても、そのまま引き継ぐ。これらのフィールドはタイムスタンプで保護されない（RFC 4998 §3）

### `#digest_algorithms` → Array<`DigestAlgorithm`>

`digest_algorithm_oids` を `DigestAlgorithm` にしたもの。

- 対応していないアルゴリズムがあれば `UnsupportedAlgorithmError`

### `#verify(data:, timestamp_validator:, at: Time.now)` → true / false

この Evidence Record が `data` の存在を証明するかを検証し、成功すれば `true`、失敗すれば `false` を返す。

- `data:`：[データ](#データ)
- `timestamp_validator:`：タイムスタンプの検証器（[TimestampValidator](#evidencerecordtimestampvalidator)）。省略できない。署名を確認せずにハッシュの連鎖だけを確認したい場合は `verify_hashes` を使う
- `at:`：検証時刻（Time）。最後のタイムスタンプは、この時刻で有効である必要がある

検証の手順:

1. **構造**: Chain が 1 つ以上あり、各 Chain に ArchiveTimeStamp が 1 つ以上ある。Chain 内の ArchiveTimeStamp はすべて同じハッシュアルゴリズムを使う。ArchiveTimeStamp に digestAlgorithm があれば、タイムスタンプの messageImprint のアルゴリズムと同じ。reducedHashtree のハッシュ値の長さが、アルゴリズムの出力長と同じ
2. **各 Chain の最初の ArchiveTimeStamp**: データのハッシュ値（グループならメンバー全員のハッシュ値）が最初の PartialHashtree に含まれ、reducedHashtree から計算したルートが messageImprint と一致する。2 つ目以降の Chain では、データのハッシュ値の代わりに `H(H(d) ‖ ha)`（`ha` はそれより前の Chain 全体のハッシュ値）を使う。連結の順序は、この固定順とソート順の両方を受け付ける（RFC 4998 の記述が食い違っているため）
3. **Chain 内の 2 つ目以降の ArchiveTimeStamp**: 直前のタイムスタンプ（DER）のハッシュ値が最初の PartialHashtree に含まれ、ルートが messageImprint と一致する
4. **時刻**: 各タイムスタンプの genTime が直前のもの以降で、最後の genTime が `at:` 以前
5. **タイムスタンプの正当性**: すべてのタイムスタンプを検証器に渡す。基準時刻は、そのタイムスタンプを保護する次のタイムスタンプの genTime。最後のタイムスタンプだけは `at:`

- reducedHashtree は、任意の形（n 分木）のものを RFC 4998 §4.3 の手順で計算する（[ReducedHashtree#root](#rootalgorithm--digest)）
- reducedHashtree がない ArchiveTimeStamp は、データのハッシュ値が messageImprint と直接一致すればよい

次の場合は `false` を返さず、例外を投げる。

| 状況 | 結果 |
|---|---|
| `data:` が[データ](#データ)の型でない | `ArgumentError` |
| `PrehashedData` に必要なアルゴリズムのハッシュ値がない | `ArgumentError` |
| `timestamp_validator:` が `call` を持たない | `ArgumentError` |
| `at:` が Time でない | `ArgumentError` |
| 対応していないアルゴリズムが使われている | `UnsupportedAlgorithmError`（「不正」ではなく「判定できない」ため） |
| 検証器が `TimestampInvalidError` 以外の例外を投げた | その例外 |

### `#verify!(data:, timestamp_validator:, at: Time.now)` → true

`verify` と同じだが、失敗した場合は `VerificationError` のサブクラスを投げる。

| 失敗した手順 | 例外 |
|---|---|
| 手順 1（構造）、手順 4 の genTime の順序 | `MalformedRecordError` |
| 手順 2・3（ハッシュの連鎖） | `HashMismatchError` |
| 手順 4 の `at:` との比較、手順 5 | `TimestampInvalidError` |

例外の `chain_index` / `ats_index` で、失敗した場所が分かる（[例外](#例外)）。

### `#verify_hashes(data:)` → true / false

手順 1〜3（構造とハッシュの連鎖）だけを検証する。タイムスタンプの署名と時刻は確認しないので、**これだけでは時刻について何も証明されない**。

例外を投げる場合は `verify` と同じ。

### `#verify_hashes!(data:)` → true

`verify_hashes` と同じだが、失敗した場合は `MalformedRecordError` または `HashMismatchError` を投げる。

### `#proven_time` → Time / nil

データの存在が証明される時刻。最初の ArchiveTimeStamp の genTime を返す。ArchiveTimeStamp がなければ `nil`。

検証に成功した Evidence Record でだけ意味がある。

### `#related_to?(other)` → true / false

`other` と同じハッシュツリーから作られたか（最初のタイムスタンプが同じか）を返す。そのような Evidence Record どうしは、タイムスタンプ更新の応答を使い回せる。

- `other` が `Record` でなければ `ArgumentError`

### `#timestamp_renewal` → `TimestampRenewal`

この Evidence Record のタイムスタンプ更新を始める。[TimestampRenewal](#evidencerecordtimestamprenewal) を参照。

- 最後の Chain がない、または空の場合は `MalformedRecordError`
- 最後の Chain の中でアルゴリズムが混在している場合は `MalformedRecordError`
- 最後の Chain が対応していないアルゴリズムを使う場合は `UnsupportedAlgorithmError`

### `#hash_tree_renewal(data:, digest_algorithm:)` → `HashTreeRenewal`

この Evidence Record のハッシュツリー更新を始める。[HashTreeRenewal](#evidencerecordhashtreerenewal) を参照。

- `data:`：[データ](#データ)
- `digest_algorithm:`：新しいアルゴリズム。今と同じアルゴリズムも指定できる
- 最初に `verify_hashes!(data: data)` を呼び、失敗すればその `VerificationError` をそのまま投げる（間違ったデータで更新すると、以降の検証がすべて失敗するため）。タイムスタンプの署名と時刻は確認しないので、必要なら更新の前に `verify` する
- `digest_algorithm:` が対応していないアルゴリズムなら `UnsupportedAlgorithmError`
- `data:` が不正な場合、`PrehashedData` に必要なアルゴリズムのハッシュ値がない場合は `ArgumentError`

### `#to_der` → String

Evidence Record の DER のバイト列。

---

## EvidenceRecord::TimestampRenewal

タイムスタンプ更新（RFC 4998 §5.2）。最後の Chain に、その Chain のタイムスタンプを保護する ArchiveTimeStamp を追加する。TSA の証明書の期限切れなどで、タイムスタンプが有効でなくなる前に行う。スレッドセーフではない。

`Record#timestamp_renewal` で作る（`new` は使わない）。

```ruby
renewal = record.timestamp_renewal
req     = renewal.timestamp_request(nonce: SecureRandom.random_number(2**64))
record2 = renewal.build(post_to_tsa(req.to_der))   # => 新しい Record
```

- データは不要で、更新の前に Evidence Record を検証しない
- 新しいタイムスタンプは、最後の Chain の**すべての**タイムスタンプ（DER）を、1 つのデータオブジェクトグループとして保護する（Bouncy Castle と同じ）
  - タイムスタンプが 1 つのときは、そのハッシュ値をそのまま messageImprint にし、reducedHashtree と digestAlgorithm を付けない
  - 2 つ以上のときは、それらのハッシュ値を並べた 1 段の reducedHashtree と digestAlgorithm を付ける
- ハッシュアルゴリズムは最後の Chain のもの。アルゴリズムを変えるにはハッシュツリー更新を使う

同じハッシュツリーから作り、同じように更新してきた Evidence Record（`related_to?` が真）は、最後の Chain のタイムスタンプが同じなので、1 つの応答で更新できる。それぞれの Evidence Record で `timestamp_renewal` を作り、同じ応答を `build` に渡す。

```ruby
renewal  = records[0].timestamp_renewal
response = post_to_tsa(renewal.timestamp_request.to_der)
renewed  = records.map { _1.timestamp_renewal.build(response) }
```

### 属性

| 属性 | 型 | 説明 |
|---|---|---|
| `record` | `Record` | 更新する Evidence Record |
| `digest_algorithm` | `DigestAlgorithm` | 最後の Chain のアルゴリズム |
| `root` | `Digest` | タイムスタンプを付ける値 |

### `#timestamp_request(nonce: nil, cert_requested: true, policy_id: nil)` → `OpenSSL::Timestamp::Request`

`root` に対するタイムスタンプ要求を返す。[TSA とのやりとり](#tsa-とのやりとり)を参照。

### `#build(response)` → `Record`

TSA の応答から、最後の Chain に ArchiveTimeStamp を追加した Evidence Record を作って返す。元の `Record` は変わらない。[TSA とのやりとり](#tsa-とのやりとり)を参照。

---

## EvidenceRecord::HashTreeRenewal

ハッシュツリー更新（RFC 4998 §5.2）。新しいハッシュアルゴリズムで、データとそれまでの Chain 全体を保護する Chain を追加する。使っているハッシュアルゴリズムが弱くなる前に行う。スレッドセーフではない。

`Record#hash_tree_renewal` で作る（`new` は使わない）。

```ruby
renewal = record.hash_tree_renewal(data: "doc-a", digest_algorithm: :sha512)
req     = renewal.timestamp_request(nonce: SecureRandom.random_number(2**64))
record2 = renewal.build(post_to_tsa(req.to_der))   # => 新しい Chain が追加された Record
```

- 新しいタイムスタンプは `H(H(d) ‖ ha)` を保護する。`H` は新しいアルゴリズム、`d` はデータ、`ha` はそれまでの ArchiveTimeStampSequence（DER）のハッシュ値。連結は固定順（Bouncy Castle や BSI のテストデータと同じ）
  - データオブジェクトなら、この値をそのまま messageImprint にし、reducedHashtree と digestAlgorithm を付けない
  - グループなら、メンバーごとに `H(H(d_i) ‖ ha)` を計算し、それらを並べた 1 段の reducedHashtree と digestAlgorithm を付ける
- 新しいアルゴリズムを Evidence Record の digestAlgorithms に追加する（すでにあれば追加しない）

### 属性

| 属性 | 型 | 説明 |
|---|---|---|
| `record` | `Record` | 更新する Evidence Record |
| `digest_algorithm` | `DigestAlgorithm` | 新しいアルゴリズム |
| `root` | `Digest` | タイムスタンプを付ける値 |

### `#timestamp_request(nonce: nil, cert_requested: true, policy_id: nil)` → `OpenSSL::Timestamp::Request`

`root` に対するタイムスタンプ要求を返す。[TSA とのやりとり](#tsa-とのやりとり)を参照。

### `#build(response)` → `Record`

TSA の応答から、新しい Chain を追加した Evidence Record を作って返す。元の `Record` は変わらない。[TSA とのやりとり](#tsa-とのやりとり)を参照。

---

## EvidenceRecord::TimestampValidator

タイムスタンプの検証器。`Record#verify` / `#verify!` の `timestamp_validator:` に渡し、各タイムスタンプが有効かを判定する。

検証器は、`call(token, at:)` を持つ任意のオブジェクト（Proc / lambda でもよい）である。

| 引数 | 型 | 説明 |
|---|---|---|
| `token` | `TimeStampToken` | 判定するタイムスタンプ |
| `at:` | Time | そのタイムスタンプが有効であるべき時刻 |

| 検証器の動作 | 扱い |
|---|---|
| 真を返す | 有効 |
| 偽（`false` / `nil`）を返す | 不正。真を返し忘れた検証器が、すべてを通してしまわないようにするため |
| `EvidenceRecord::TimestampInvalidError` を投げる | 不正 |
| それ以外の例外を投げる | 捕まえずに、そのまま `verify` / `verify!` から投げる。検証器のバグが「不正」に紛れないようにするため |

`verify!` は、検証器が投げた `TimestampInvalidError` に失敗した場所（`chain_index` / `ats_index`）を付けて投げ直す。元の例外は `cause` で取得できる。

```ruby
# 同梱の検証器に、独自の確認（失効の確認など）を加える例
openssl = EvidenceRecord::TimestampValidator::OpenSSL.new(store: store)
validator = ->(token, at:) { openssl.call(token, at: at) && not_revoked?(token.certificates.first, at) }
record.verify(data: "doc-a", timestamp_validator: validator)
```

---

## EvidenceRecord::TimestampValidator::OpenSSL

OpenSSL で、タイムスタンプの署名と証明書チェーンを検証する検証器。

```ruby
store = OpenSSL::X509::Store.new
store.add_cert(tsa_root_certificate)
validator = EvidenceRecord::TimestampValidator::OpenSSL.new(store: store)
```

確認すること:

- トークンの署名
- 署名者の証明書が、トークンの ESS signing certificate 属性で指定されたものであること
- 署名者の証明書の用途（extendedKeyUsage が timeStamping）
- 署名者の証明書から、`store` の信頼する証明書までのチェーンが `at:` の時刻で有効であること

確認しないこと:

- 失効（CRL / OCSP）。`store` に CRL を入れて失効の確認を有効にした場合を除く
- 使われているアルゴリズムが、今も安全と見なされているか

これらが必要な場合は、独自の検証器を作る。

### `TimestampValidator::OpenSSL.new(store:)`

- `store:`：信頼する証明書（TSA のルート証明書など）を入れた `OpenSSL::X509::Store`。それ以外は `ArgumentError`

**呼び出しのたびに `store` の検証時刻（`Store#time=`）を書き換える。** この検証器専用の Store を渡し、ほかの処理と共有しないこと。

### `#call(token, at:)` → true

`token` が `at:` の時刻で有効なら `true` を返す。不正なら `TimestampInvalidError` を投げる。

- `token` が `TimeStampToken` でない、`at:` が Time でない場合は `ArgumentError`

---

## EvidenceRecord::Chain

ArchiveTimeStampChain（RFC 4998 §5）。同じハッシュアルゴリズムを使い、それぞれが直前のタイムスタンプを保護する ArchiveTimeStamp の並び。アルゴリズムを表すフィールドは持たない。[DER のデータ構造](#der-のデータ構造)の 1 つ。

### `Chain.from_der(der)` → `Chain`

DER のバイト列から読み込む。不正な場合は `ParseError`。

### インスタンスメソッド

| メソッド | 戻り値 | 説明 |
|---|---|---|
| `archive_timestamps` | Array<`ArchiveTimeStamp`> | 古いものから順に並ぶ（frozen） |
| `to_der` | String | DER のバイト列 |

---

## EvidenceRecord::ArchiveTimeStamp

ArchiveTimeStamp（RFC 4998 §4.1）。タイムスタンプと、データ（または直前のタイムスタンプ）からタイムスタンプの対象のルートまでの reducedHashtree。[DER のデータ構造](#der-のデータ構造)の 1 つ。

### `ArchiveTimeStamp.from_der(der)` → `ArchiveTimeStamp`

DER のバイト列から読み込む。不正な場合は `ParseError`。

### 属性

| 属性 | 型 | 説明 |
|---|---|---|
| `timestamp` | `TimeStampToken` | timeStamp フィールド |
| `reduced_hashtree` | `ReducedHashtree` / nil | reducedHashtree フィールド。なければ `nil`（タイムスタンプが 1 つのハッシュ値を直接保護している） |
| `attributes` | String / nil | attributes フィールドの DER（`[1]` のタグを含む）。なければ `nil` |

attributes の中身は解釈しない。このフィールドはタイムスタンプ更新では保護されない（ハッシュツリー更新では保護される）。

### `#digest_algorithm_oid` → String

reducedHashtree のハッシュアルゴリズムの OID。digestAlgorithm フィールドがなければ、タイムスタンプの messageImprint のアルゴリズム（RFC 4998 §4.1）。

### `#digest_algorithm` → `DigestAlgorithm`

`digest_algorithm_oid` を `DigestAlgorithm` にしたもの。

- 対応していないアルゴリズムなら `UnsupportedAlgorithmError`

### `#to_der` → String

ArchiveTimeStamp の DER のバイト列。

---

## EvidenceRecord::TimeStampToken

RFC 3161 のタイムスタンプトークン（ArchiveTimeStamp の timeStamp フィールド）。TSTInfo の値を読むだけで、署名は確認しない（それは[検証器](#evidencerecordtimestampvalidator)の役割）。[DER のデータ構造](#der-のデータ構造)の 1 つ。

### `TimeStampToken.from_der(der)` → `TimeStampToken`

ContentInfo（signedData）の DER のバイト列から読み込む。不正な場合は `ParseError`。

### 属性

| 属性 | 型 | 説明 |
|---|---|---|
| `gen_time` | Time | genTime。UTC で、秒未満も保持する |
| `message_imprint` | `Digest` | タイムスタンプの対象のハッシュ値 |
| `hash_algorithm_oid` | String | messageImprint のアルゴリズムの OID |
| `serial_number` | Integer | serialNumber |
| `policy_id` | String | policy の OID |
| `nonce` | Integer / nil | nonce。なければ `nil` |

### `#hash_algorithm` → `DigestAlgorithm`

`hash_algorithm_oid` を `DigestAlgorithm` にしたもの。

- 対応していないアルゴリズムなら `UnsupportedAlgorithmError`

### `#certificates` → Array<`OpenSSL::X509::Certificate`>

トークンに含まれる証明書（通常は TSA の証明書と、そのチェーン）。次の更新時期の判断（`not_after`）などに使う。

### `#to_der` → String

タイムスタンプトークンの DER のバイト列。

---

## EvidenceRecord::ReducedHashtree

reducedHashtree（RFC 4998 §4.1）。1 つの葉からルートを計算するのに必要な PartialHashtree の並び。frozen である。

### `ReducedHashtree.new(partial_hashtrees)`

- `partial_hashtrees`：[ハッシュ値](#引数のハッシュ値)の空でない配列の、空でない配列。各要素は `Digest` に変換して保持する
- 型が違う場合、空の配列を含む場合は `ArgumentError`

### 属性

| 属性 | 型 | 説明 |
|---|---|---|
| `partial_hashtrees` | Array<Array<`Digest`>> | PartialHashtree の並び（frozen）。最初のものは葉（グループならメンバー全員のハッシュ値）と、場合によってはその兄弟。以降は、各段の兄弟 |

### `#leaf_values` → Array<`Digest`>

最初の PartialHashtree。

### `#root(algorithm)` → `Digest`

RFC 4998 §4.3 の手順でルートを計算する。

- `algorithm`：Symbol または `DigestAlgorithm`
- 値が 1 つの PartialHashtree は、その値をそのまま使う。値が複数あれば、値をバイト列の昇順に並べて連結したもののハッシュ値を使う
- 2 つ目以降の PartialHashtree は、前の段の結果を加えて、同じように計算する
- ハッシュ値の長さは確認しない（`Record#verify` では確認する）

### `#==(other)` / `#eql?(other)` / `#hash`

`partial_hashtrees` の値で比較する。

---

## EvidenceRecord::Digest

ハッシュ値を表す値オブジェクト。中身は BINARY エンコーディングのバイト列で、frozen である。アルゴリズムは持たない（RFC 4998 では、アルゴリズムは文脈で決まるため）。ct_merkle の `CTMerkle::Digest` と同じ仕様。

```ruby
d = EvidenceRecord::Digest.from_hex("2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824")
d.to_hex       # => "2cf24dba..."
d.to_base64    # => "LPJNul+wow4m6DsqxbninhsWHlwfp0JecwQzYpOLmCQ="
d.bytesize     # => 32
p d            # => #<EvidenceRecord::Digest 2cf24dba...>
```

### `Digest.new(bytes)`

バイト列から作る。エンコーディングに関係なく、BINARY のコピーとして保持する。

- `bytes` が String でない場合は `ArgumentError`
- 長さは確認しない

### `Digest.from_hex(str)` → `Digest`

hex 文字列から作る。大文字・小文字のどちらでもよい。

- `str` が String でない場合、または hex として不正な場合（奇数桁、hex 以外の文字、空白を含むなど）は `ArgumentError`

### `Digest.from_base64(str)` → `Digest`

base64 文字列（RFC 4648、改行なし、パディングあり）から作る。

- `str` が String でない場合、または base64 として不正な場合（改行を含む、パディングがないなど）は `ArgumentError`

### インスタンスメソッド

| メソッド | 戻り値 | 説明 |
|---|---|---|
| `to_binary` | String | 生のバイト列（BINARY エンコーディング、frozen） |
| `to_hex` | String | 小文字の hex 文字列 |
| `to_base64` | String | base64 文字列（RFC 4648、改行なし） |
| `to_s` | String | `to_hex` と同じ |
| `inspect` | String | `#<EvidenceRecord::Digest 2cf24dba...>` の形式（hex は省略せずに全桁を表示） |
| `bytesize` | Integer | バイト数 |
| `==(other)` | true / false | `other` が `Digest` または String の場合は、バイト列だけで比較する（String のエンコーディングは見ない）。それ以外は常に `false` |
| `eql?(other)` | true / false | `other` が `Digest` で、バイト列が同じ場合だけ `true` |
| `hash` | Integer | `eql?` と一貫したハッシュ値。`Digest` を Hash のキーに使える |

`to_str` は定義していない。そのため、`String#==` は `Digest` と比較すると常に `false` を返す。String と比較するときは、`digest == str` のように `Digest` を左辺に置く。

---

## EvidenceRecord::DigestAlgorithm

対応しているハッシュアルゴリズム。インスタンスは下の定数の 3 つだけで、frozen である（`new` は使わない）。

| 定数 | `name` | `oid` | `digest_size` |
|---|---|---|---|
| `DigestAlgorithm::SHA256` | `:sha256` | `"2.16.840.1.101.3.4.2.1"` | 32 |
| `DigestAlgorithm::SHA384` | `:sha384` | `"2.16.840.1.101.3.4.2.2"` | 48 |
| `DigestAlgorithm::SHA512` | `:sha512` | `"2.16.840.1.101.3.4.2.3"` | 64 |

`DigestAlgorithm::ALL` は、この 3 つの配列。

### `DigestAlgorithm.fetch(value)` → `DigestAlgorithm`

Symbol（`:sha256` など）から取得する。`DigestAlgorithm` を渡すと、それをそのまま返す。

- 対応していない Symbol なら `UnsupportedAlgorithmError`
- Symbol / `DigestAlgorithm` 以外なら `ArgumentError`

### `DigestAlgorithm.from_oid(oid)` → `DigestAlgorithm`

OID の文字列から取得する。

- 対応していない OID なら `UnsupportedAlgorithmError`

### インスタンスメソッド

| メソッド | 戻り値 | 説明 |
|---|---|---|
| `name` | Symbol | `:sha256` など |
| `oid` | String | OID の文字列 |
| `digest_size` | Integer | 出力のバイト数 |
| `digest(*parts)` | String | `parts`（String）を連結したもののハッシュ値。BINARY エンコーディングの String を返す |
| `to_s` | String | `"sha256"` など |

---

## EvidenceRecord::HashTree

`Generator` が使うハッシュツリー。ハッシュの計算だけを行い、ASN.1 もタイムスタンプも扱わない。通常は直接使う必要はない。スレッドセーフではない。

```ruby
tree = EvidenceRecord::HashTree.new(digest_algorithm: :sha256)
tree.add([OpenSSL::Digest.digest("SHA256", "doc-a")])   # => 0
tree.add([h_meta, h_body])                               # => 1（グループ）
tree.root                                                # => #<EvidenceRecord::Digest ...>
tree.reduced_hashtree(0)                                 # => #<EvidenceRecord::ReducedHashtree ...>
```

ツリーの形は Bouncy Castle の `BinaryTreeRootCalculator` と同じ。

- 葉のハッシュ値は、データオブジェクトならそのハッシュ値、グループならメンバーのハッシュ値をバイト列の昇順に並べて連結したもののハッシュ値
- 葉をハッシュ値の昇順に並べ、隣どうしを組にした 2 分木にする。組にした 2 つの値も、昇順に並べて連結してからハッシュする
- 段の要素数が奇数なら、最後の要素はそのまま上の段に上げる

### `HashTree.new(digest_algorithm: :sha256)`

アルゴリズムを指定して、空のツリーを作る。

### `#add(member_hashes)` → Integer

葉を追加し、その位置（0 から始まる追加順の番号）を返す。

- `member_hashes`：[ハッシュ値](#引数のハッシュ値)の配列。データオブジェクトなら `[ハッシュ値]`、グループならメンバー全員のハッシュ値
- Array でない、空、長さがアルゴリズムの出力長と違うハッシュ値を含む場合は `ArgumentError`

### `#size` → Integer

葉の数。

### `#empty?` → true / false

葉が 1 つもないか。

### `#digest_algorithm` → `DigestAlgorithm`

ツリーのアルゴリズム。

### `#root` → `Digest`

ルートを返す。

- 葉が 1 つもなければ `EvidenceRecord::Error`

### `#leaf_hash(index)` → `Digest`

`index` の葉のハッシュ値を返す。

- `index` が Integer でなければ `ArgumentError`、`0...size` の範囲外なら `IndexError`

### `#reduced_hashtree(index)` → `ReducedHashtree`

`index` の葉の reducedHashtree を返す。最初の PartialHashtree は葉（グループならメンバー全員のハッシュ値）だけで、以降は各段の兄弟である。

- `index` が Integer でなければ `ArgumentError`、`0...size` の範囲外なら `IndexError`

---

## 例外

```
StandardError
├─ ArgumentError                               引数の型や範囲が不正
├─ IndexError                                  HashTree の範囲外のインデックス
└─ EvidenceRecord::Error                       このライブラリの例外の基底クラス
   ├─ EvidenceRecord::ParseError               DER として不正、または RFC 4998 / RFC 3161 の構造に合わない
   ├─ EvidenceRecord::UnsupportedAlgorithmError 対応していないハッシュアルゴリズム
   ├─ EvidenceRecord::TimestampResponseError   TSA の応答が使えない（拒否、要求との不一致など）
   └─ EvidenceRecord::VerificationError        verify! / verify_hashes! が失敗した
      ├─ EvidenceRecord::MalformedRecordError  Evidence Record の構造が不正（空の Chain、Chain 内でアルゴリズムが混在など）
      ├─ EvidenceRecord::HashMismatchError     データが含まれていない、計算したルートが messageImprint と一致しない
      └─ EvidenceRecord::TimestampInvalidError タイムスタンプが不正（検証器が不正と判定した、検証時刻より後）
```

- 呼び出し方の誤り（型が違う、`PrehashedData` に必要なハッシュ値がないなど）は `ArgumentError` とする。`verify` でも `false` にはならず、例外になる
- 検証の失敗は `VerificationError` のサブクラスで表す。`verify` / `verify_hashes` は `false` を返し、`verify!` / `verify_hashes!` は例外を投げる
- `EvidenceRecord::Error` そのものは、`Generator` の状態の誤り（`build` の後の `add`、データがない状態での `root` など）と、空の `HashTree` の `root` で投げる

### `VerificationError#chain_index` → Integer / nil

検証に失敗した Chain の位置（0 から）。特定の ArchiveTimeStamp に結びつかない失敗（Chain が 1 つもないなど）では `nil`。

### `VerificationError#ats_index` → Integer / nil

検証に失敗した ArchiveTimeStamp の、Chain の中での位置（0 から）。特定の ArchiveTimeStamp に結びつかない失敗では `nil`。
