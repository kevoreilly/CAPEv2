# Windows VM 内の定期メトリクス取得

検体を実行する Windows VM 内で、API コールの有無によらず時刻と負荷を定期取得する。
`codex/APICall-metrics` の変更は不要で、通常の capemon と組み合わせて使用できる。
対象は Windows Analyzer。Linux VM は対象外。

## 有効化

ホストの `conf/auxiliary.conf` の `[auxiliary_modules]` に以下を設定する。
既存ファイルへ設定を追加すること。既定では無効。

```ini
periodic_metrics = yes
periodic_metrics_interval = 1
```

間隔は秒単位で、0.1〜60 秒。小数も使用できる。
検体投入時の options に `periodic_metrics_interval=0.5` を指定すると、その解析だけ間隔を変更できる。
不正値は警告を出し、1 秒に戻す。有効化はホストの設定で行う。
ゲストへの追加 Python パッケージ導入や capemon の再ビルドは不要。
通常の解析開始時にホストから配布される Analyzer に新規モジュールが含まれていれば動作する。

## 動作と保存先

Auxiliary の開始直後に最初のサンプルを取得し、解析終了まで専用スレッドで採取する。
待機は単調増加時計を使う。採取が間隔を超えた場合は過ぎた採取枠を飛ばすため、厳密なリアルタイム周期は保証しない。
各サンプルを VM の一時ファイルに書き、解析終了時に既存の ResultServer 経由で回収する。
採取中のネットワーク送信は行わない。

ホスト上の出力先:

```text
storage/analyses/<analysis_id>/aux/periodic_metrics.jsonl
```

1 行が 1 サンプルの JSON。Web UI へのグラフ表示・レポート JSON への統合は行わず、時系列の原データを保存する。
回収には既存のアップロード上限・接続設定が適用される。VM が強制停止した場合や回収が失敗した場合、ホストに結果が残る保証はない。
長時間解析や短い間隔ではファイル容量と採取負荷が増える。

## 記録項目

| 項目 | 意味 |
| --- | --- |
| `schema_version` | 出力形式のバージョン。現在は 1 |
| `timestamp_utc` | VM 内の UTC 壁時計。ISO 8601 形式 |
| `monotonic_ns` | VM 内の `perf_counter_ns`。起点は任意 |
| `elapsed_seconds` | この収集の開始からの経過秒数 |
| `interval_seconds` | 設定された採取間隔。実際の間隔は時刻差から確認する |
| `system.cpu_percent` | 前回の有効サンプルからの VM 全体 CPU 使用率（0〜100） |
| `system.memory_load_percent` | VM 全体の物理メモリ使用率 |
| `system.total_physical_bytes` / `available_physical_bytes` | VM の物理メモリ総量・空き容量 |
| `processes[].pid` | Analyzer が監視対象として通知した PID |
| `processes[].cpu_percent` | 前回との差分 CPU 使用率。1 コア分を 100% とし、複数コア使用時は 100% を超える |
| `processes[].creation_time_100ns` | PID 再利用を識別するプロセス生成時刻。Windows FILETIME の 100ns 単位 |
| `processes[].cpu_time_100ns` | プロセスの累積カーネル時間 + ユーザー時間（100ns 単位） |
| `processes[].working_set_bytes` / `peak_working_set_bytes` | 現在・最大のワーキングセット |
| `processes[].private_usage_bytes` | プライベートコミット量 |
| `processes[].pagefile_usage_bytes` / `peak_pagefile_usage_bytes` | Windows が返す現在・最大のコミット量。物理的なページファイル使用量ではない |
| `errors` / `processes[].error` / `processes[].memory_error` | 取得失敗。メモリ単独の失敗は Win32 エラーコード |

最初の CPU 使用率、PID 再利用後、取得失敗の次の CPU 使用率は `null`。
取得できなかったメモリ項目は省略する。欠損を 0 として扱わない。
プロセス終了・アクセス拒否は当該 PID のエラーとして記録し、他の採取を継続する。
監視 PID のみを列挙するため、VM 内の全プロセス一覧にはならない。短命なプロセスは周期の間に終了し、採取できない場合がある。
`system` には OS、Analyzer、他のプロセスの負荷も含む。
この定期サンプリングから個々の API コールの実行時間を求めることはできない。

## ローカル検証

Windows 上で `analyzer/windows` を作業ディレクトリにして実行する。

```powershell
python -m unittest discover -s tests/modules/auxiliary -p test_periodic_metrics.py -v
```

CPU 差分計算、欠損・PID 再利用、間隔検証、周期超過時の動作、停止、JSONL 回収処理、実際の Win32 API による自プロセスの取得を検証する。
VM と ResultServer を使った実際の検体解析・回収は別途確認する必要がある。
