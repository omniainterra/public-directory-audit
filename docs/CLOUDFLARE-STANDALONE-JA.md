# 単一ファイル版：Cloudflare D1 暗号化保管ゲートウェイ

このファイルは、Cloudflare管理画面のエディターで扱えるよう、２つの監査済みモジュールを一つにまとめたものです。

配置ファイル：`deploy/cloudflare-private-gateway-single-file.mjs`

最初の確認では、秘密情報を一切設定せずに導入できます。認証や暗号化公開鍵の識別値などの必須設定が欠けている間、D1の読み書きAPIは503を返して停止します。`GET /health`のみ、調査・メール送信が無効であることを示す固定の応答を返します。

有効化には既存の４変数に加え、最新版で `ACCESS_AUD` と `ACCESS_ALLOWED_EMAIL` が必須です。すべて揃うまで、有効化の値を登録しないでください。個人用トークンや秘密鍵は、公開リポジトリやチャットへ貼り付けないでください。

**重要：Workers.dev のURLは公開されています。** このゲートウェイは非公開ソースとして扱えるものではなく、HTTPアクセスを認証で保護する設計です。実データは独立した秘密鍵による暗号化を前提とし、実際の安全性は本番環境で別途検証します。

このコードは事業者サイトを取得しません。Cloudflare上の自動実行、外部サイト通信、データ移管も含まれません。現在の `public-directory-audit-pilot` を変更しないでください。


## 必須追加認証：Cloudflare Access

最新版では、クラウド側で検証済みの `ctx.access` が存在し、さらに `ACCESS_AUD` と `ACCESS_ALLOWED_EMAIL` が一致しなければ、データベースへの全アクセスを403で拒否します。

Cloudflare Workers & Pages → 対象Worker → Access → 「Protect this Worker behind Access」から、**All traffic** を選択し、オーナーのメールアドレス１つだけを許可してください。全利用者許可、ドメイン全体許可は使用しないでください。

Cloudflare Accessには無料プランがございますが、選択する契約が無料であることを画面で確認してから操作してください。Access設定が終わるまで、`STORAGE_ONLY_ENABLED`を追加しないでください。

既存の旧版Workerは /internal が503を返します。こちらの改良版をデプロイすると、Access未構成時は403を返します。正常な安全動作です。

手順と認証後の検証方法は [Cloudflare Access 本番切替手順](./CLOUDFLARE-ACCESS-CUTOVER-JA.md) を参照してください。
