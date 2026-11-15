# 変更履歴

## [Unreleased] - 未リリース

Not yet.

## [0.1.0] - 2026-11-15

初版リリース

### 追加

- `EvidenceRecord::Generator`：多数のデータの Evidence Record を、1 つのタイムスタンプでまとめて生成
  - `add` でデータオブジェクトまたはデータオブジェクトグループを追加
  - `timestamp_request` でタイムスタンプ要求（`OpenSSL::Timestamp::Request`）を作り、`build` で TSA の応答から Evidence Record を作る（TSA との通信は利用者が行う）
  - `build` は、応答の状態、messageImprint のアルゴリズムと値、nonce / policy を確認する
- `EvidenceRecord::Record`：Evidence Record を表す値オブジェクト
  - `from_der` / `to_der` で DER と相互に変換（読み込んだバイト列をそのまま保持する）
  - `verify` / `verify!` で、データからすべてのタイムスタンプまでのハッシュの連鎖、時刻の順序、各タイムスタンプの正当性を検証。任意の形（n 分木）のハッシュツリーを RFC 4998 の手順で検証する
  - `verify_hashes` / `verify_hashes!` で、ハッシュの連鎖だけを検証
  - `proven_time`、`related_to?`、`chains` などで中身を参照
- `EvidenceRecord::TimestampRenewal`（`Record#timestamp_renewal`）：タイムスタンプ更新。最後の Chain のすべてのタイムスタンプを保護する ArchiveTimeStamp を追加する。同じハッシュツリーから作った Evidence Record どうしで、TSA の応答を使い回せる
- `EvidenceRecord::HashTreeRenewal`（`Record#hash_tree_renewal`）：ハッシュツリー更新。新しいハッシュアルゴリズムで、データとそれまでの Chain 全体を保護する Chain を追加する
- `EvidenceRecord::TimestampValidator::OpenSSL`：タイムスタンプの署名と証明書チェーンを OpenSSL で検証する検証器。`call(token, at:)` を持つ任意のオブジェクトに差し替えられる
- `EvidenceRecord::DataGroup`：データオブジェクトグループ
- `EvidenceRecord::PrehashedData`：データ本体の代わりに渡す、計算済みのハッシュ値。生成、検証、更新のすべてで使える
- `EvidenceRecord::Chain`、`ArchiveTimeStamp`、`TimeStampToken`、`ReducedHashtree`：Evidence Record の構造を表す値オブジェクト
- `EvidenceRecord::Digest`：ハッシュ値を表す値オブジェクト。hex / base64 との相互変換
- `EvidenceRecord::DigestAlgorithm`：対応するハッシュアルゴリズム（SHA-256、SHA-384、SHA-512）
- `EvidenceRecord::HashTree`：Evidence Record の生成に使うハッシュツリー（Bouncy Castle と同じ形の 2 分木）
- 例外クラス `EvidenceRecord::Error`、`ParseError`、`UnsupportedAlgorithmError`、`TimestampResponseError`、`VerificationError`、`MalformedRecordError`、`HashMismatchError`、`TimestampInvalidError`
- TSA の応答は、長さの書き方が BER のものも受け付け、トークンを DER に直して Evidence Record に入れる
- 対応する Ruby のバージョン：3.4、4.0（Ruby 3.3 に同梱の openssl gem では、タイムスタンプの証明書を指定した時刻で検証できないため対象外）

### 確認済みの相互運用性

- BSI のテストデータ（ERS-Testtool、TR-ESOR C.2）の Evidence Record を検証できる
- Bouncy Castle 1.87（`org.bouncycastle.tsp.ers`）と双方向に相互運用できる。このライブラリで生成・更新した Evidence Record を Bouncy Castle で検証でき、Bouncy Castle で生成・更新したものをこのライブラリで検証できる

### 既知の差異

- ハッシュツリー更新での `H(d)` と `ha` の連結順は、RFC 4998 の本文と図で記述が食い違っている（Errata 7411）。生成は固定順（Bouncy Castle、BSI のテストデータと同じ）とし、検証は固定順とソート順の両方を受け付ける
- メンバーが 1 つのデータオブジェクトグループは、Bouncy Castle ではグループとして検証できない（メンバーをデータオブジェクトとして渡せば検証できる）。Bouncy Castle 自身が生成した場合も同じ
- Bouncy Castle と違い、すべての Chain をデータと照合し、すべてのタイムスタンプを検証器に渡す

[0.1.0]: https://github.com/xketanaka/evidence_record/releases/tag/v0.1.0
