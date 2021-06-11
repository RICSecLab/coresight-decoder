# Fib
同じプログラムに対してトレースを行った複数のトレースデータから、同じエッジカバレッジが計算できるかを確かめるテストである。プログラムの実行パスは決定論的に決まるため、エッジカバレッジは一致するはずである。ただし、データアクセス等によって発生する例外は非決定的に発生するため、そのような例外を考慮するとエッジカバレッジは変わる可能性があるが、現在は例外によって発生するエッジは無視している。

## テスト方法
フィボナッチ数列を計算するプログラムである`fib.c`をトレースした結果を`trace1`, `trace2`, `trace3`, `trace4`として保存してある。
これを用いて、エッジカバレッジを計算する。
出力は、`trace1_edge_coverage.out`, `trace2_edge_coverage.out`, `trace3_edge_coverage.out`, `trace4_edge_coverage.out`として保存する。

`trace1_edge_coverage.out`, `trace2_edge_coverage.out`, `trace3_edge_coverage.out`, `trace4_edge_coverage.out`をそれぞれ比較して、
同じエッジカバレッジが計算できるかを確かめている。
