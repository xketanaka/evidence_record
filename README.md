# evidence_record

[RFC 4998](https://www.rfc-editor.org/rfc/rfc4998)(Evidence Record Syntax, ERS)に準拠した Evidence Record の Ruby 実装。

## 機能

- 文字列または任意のハッシュ値の(データオブジェクトまたはデータオブジェクトグループの) Evidence Record の生成
- タイムスタンプ更新、ハッシュツリー更新
- 外部から与えられた Evidence Record の検証
- タイムスタンプの取得(TSA との通信)は対象外とする
- 依存ライブラリなし

## 開発

```bash
bundle install
bundle exec rake test
```

BSI のテストデータを使うテストは、データを取得してから実行する。データがない場合、そのテストはスキップされる。
テストデータは [bcgit/bc-test-data](https://github.com/bcgit/bc-test-data) の `tsp/20170316_Testdaten`（BSI TR-ESOR / ERS テストツール）から、固定したコミットのものを取得し、SHA-256 で内容を確認する。ライセンスが明示されていないため、このリポジトリには含めない。


```bash
bundle exec rake test:fetch_vectors   # test/fixtures/bsi に取得する
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
