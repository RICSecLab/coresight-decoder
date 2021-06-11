# Branches
すべての分岐命令に対して、正しくエッジカバレッジを計算できているか確かめるためのテストである。

## 分岐命令一覧
Arm Embedded Trace Macrocell Architecture Specification ETMv4.0 to ETMv4.6 F.1 Branch instructionsによると、分岐命令一覧は以下のようである。
* A64 instruction set, direct branches:
  * B
  * B.cond
  * CBZ/CBNZ
  * TBZ/BNZ
  * BL
  * ISB
  * ~WFI, WFE~ （ThunderX2のTRCIDR2.WFXMODEが0なので、分岐命令に分類されない。）

* A64 instruction set, indirect branches:
  * RET
  * BR
  * BLR
  * ~ERET~ （ユーザ空間のプログラムでは呼ばれないため、現在未対応。）
  * ~ERETAA/ERETAB, RETAA/RETAB, BRAA/BRAB, BRAAZ/BRABZ, BLRAA/BLRAB, BLRAAZ/BLRABZ~ （ThunderX2がポインタ認証未対応のため、現在未対応。）

## テスト方法
上記の分岐命令がすべて含まれるコードである`branches.c`をトレースした結果を`trace1`, `trace2`, `trace3`, `trace4`として保存してある。
これを用いて、エッジカバレッジを計算する。ただし、必要なエッジカバレッジの範囲を指定して、必要な箇所だけに限定している。
出力は、`trace1_edge_coverage.out`, `trace2_edge_coverage.out`, `trace3_edge_coverage.out`, `trace4_edge_coverage.out`として保存する。

また、その範囲内のエッジカバレッジを事前に手計算で計算し、期待されるエッジカバレッジを`expected_edge_coverage.out`として保存してある。

`trace1_edge_coverage.out`, `trace2_edge_coverage.out`, `trace3_edge_coverage.out`, `trace4_edge_coverage.out`と、
`expected_edge_coverage.out`を比較することで、すべての分岐命令に対して、エッジカバレッジを正しく復元できているかを確かめている。
