# Cloudflare Access 本番切替手順（認証設定と検証）

**この手順は、非公開保存専用の Worker に限ります。実装・デプロイ・有効化・D1 書き込みの許可ではありません。** 別の公開パイロット、他の Workers、実サイト巡回、営業送信は変更しません。

## 前提

- Workers Free / D1 Free / Zero Trust Free を画面で確認します。課金プラン、従量課金、有料ブラウザー操作を開始しません。Cloudflare Zero Trust Free の初期設定では支払い情報入力を求められる場合があります。無料であることを確認できない場合はそこで停止します。
- 非公開保存専用 Worker を選び、`DB` が隔離した D1 に接続され、`MAX_REQUESTS_PER_DAY=1` であることを確認します。これは予約数の制限であり、実サイトへの巡回量ではありません。
- 既存の公開用パイロットには Access を付けず、アカウント全体の「Protect all Workers」を使用しません。
- 秘密鍵・生の Bearer トークン・顧客データ・営業候補 URL をチャットや公開 GitHub に登録しません。

## ステップ１：Access を単独 Worker の全経路に設定する

Cloudflare Dashboard > Workers & Pages > **非公開保存用 Worker** > Access >
`Protect this Worker behind Access` を開き、**All traffic**（Production と Previews の両方）を選びます。**Previews only を選ばない**でください。

認証ポリシーは、オーナーのメールアドレスただ１件を許可するものを用います。簡易画面の `Cloudflare account` はアカウントの他メンバーを含む可能性があり、`Email domain` はドメイン内の全員を許可するため、そのままでは単独メール限定の要件を満たしません。必要であれば Zero Trust > Access > Policies で **Emails = 具体的な１アドレス**の Allow ポリシーを作り、Worker 用アプリに割り当てます。Everyone、全メールドメイン、全 Workers 対象は選ばないでください。

ポリシーの適用と無料プラン確認後、Worker の `Access` タブで **All traffic に保護がかかっていること**を再確認します。上流の Access が有効であれば、未認証のブラウザーはサインイン画面または拒否に進みます。

## ステップ２：ソースと設定値を一致させる（別途デプロイ承認が必要）

`deploy/cloudflare-private-gateway-single-file.mjs` の最新版が Cloudflare に反映済みか、**実 Worker のコードを比較して確認**します。GitHub の CI 成功は本番反映・認証確認の証拠ではありません。反映すると `/internal/` は `ctx.access` による Cloudflare 側の本人認証を要求します。

Worker の Environment Variables / Secrets に設定する値：

- `ACCESS_AUD` — 対象 Access Application の Audience Tag（ポリシーの確認画面から取得）
- `ACCESS_ALLOWED_EMAIL` — 許可された本人のメールアドレス１件
- `AUTH_TOKEN_SHA256` — 安全確認済みの別端末で生成した強い Bearer トークンの SHA-256 値（**生トークンではない**）
- `PUBLIC_KEY_FINGERPRINT` — 独立した実運用 RSA-3072 公開鍵の SHA-256 指紋（公開リポジトリのテスト用鍵は禁止）
- `MAX_REQUESTS_PER_DAY=1` — 初期値を維持
- `STORAGE_ONLY_ENABLED=I_UNDERSTAND_PRIVATE_STORAGE_ONLY` — 最後の安全確認を通過し、個別承認を得るまで **設定しない**

秘密鍵は Worker、チャット、ブラウザー、公開リポジトリへ一切置きません。公開用 Worker に DB バインディングは付けません。

## ステップ３：検証順序（承認された小規模操作だけ）

1. **未認証確認**：匿名で `/internal/v1/reservations` へアクセスし、Cloudflare Access によるサインイン要求または拒否であることを確認します。ログイン画面を HTTP 200 の成功と誤認しません。
2. **認証済み・未有効化確認**：本人が Access を通過しても、必要な変数が不足している間は D1 API が拒否されることを確認します。GitHub 最新コードなら `CLOUDFLARE_ACCESS_REQUIRED` / `PRIVATE_STORAGE_NOT_CONFIGURED` を切り分けられますが、旧 Worker の応答から新版の稼働を推定しません。
3. **資格情報の二重確認**：有効化後は Access と Bearer の両方が必須であり、片方だけで D1 を読み書きできないことを確認します。Access の audience と identity は Worker が受信した任意ヘッダーではなく、`ctx.access` で検証します。
4. **D1 最小テスト**：別途許可を得た架空の一件だけを暗号化して、予約・保存・暗号文再読込・重複防止・日次枠超過を確認します。実データ投入は別承認です。
5. **終了判定**：Cloudflare Dashboard の Worker バージョン、Access Policy、D1 テーブル、無料枠、実テスト結果がすべて揃うまで「Cloudflare 完成」と記録しません。

Cloudflare の 2026年8月更新の公式説明：
https://developers.cloudflare.com/workers/configuration/cloudflare-access/

無料 D1 では日次読み書き制限到達時にクエリーが停止します。営業送信可否は別途連邦法・州法の確認が必要であり、この Worker の成功とは切り離します。
