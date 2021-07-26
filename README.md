# coresight-decoder
Experimental CoreSight Decoder

## ライブラリのインターフェース

### libcsdec_init()
```c
libcsdec_t libcsdec_init(
    int binary_file_num, const char *binary_file_path[],
    void *bitmap_addr, int bitmap_size);
```

libcsdec_write_bitmap()の読み出しで使う、オブジェクトを初期化し、そのオブジェクトのポインタを返す。

* 引数:
    * `binary_file_num`: トレースを行うバイナリファイルの数
    * `binary_file_path`: トレースを行うバイナリファイルのパスを示す配列
    * `bitmap_addr`: ビットマップを書き込む先頭アドレス
    * `bitmap_size`: ビットマップのサイズ
* 戻り値:
    * libcsdec内で使うオブジェクトのポインタ（このオブジェクトの解放はライブラリ使用者が行う）

### libcsdec_write_bitmap()
```c
libcsdec_result_t libcsdec_write_bitmap(const libcsdec_t libcsdec,
    const void *trace_data_addr, const size_t trace_data_size,
    char trace_id, int memory_map_num,
    const struct libcsdec_memory_map libcsdec_memory_map[]);
```

トレースデータとlibcsdec_init()で登録したバイナリファイルから、エッジカバレッジを計算し、ビットマップに書き込む。

* 引数:
    * `libcsdec`: トレースを行うバイナリファイルの数
    * `trace_data_addr`: トレースデータが書き込まれているアドレス（ライブラリはこの領域を読むだけ）
    * `trace_data_size`: トレースデータのサイズ
    * `trace_id`: トレースID
    * `memory_map_num`: メモリマップの数
    * `libcsdec_memory_map`: トレースを行ったプロセスのメモリマップ（すべての実行領域の情報が必要）
        * `libcsdec_memory_map::start`:　マップされている開始アドレス
        * `libcsdec_memory_map::end`:  マップされている終了アドレス
        * `libcsdec_memory_map::path`: マップされてているバイナリファイルのパス

* 戻り値:
    * `libcsdec_result_t` 実行が正解したかどうかの情報
        * `LIBCEDEC_SUCCESS`: 実行成功
        * `LIBCSDEC_ERROR`:  実行失敗
        * `LIBCSDEC_ERROR_OVERFLOW_PACKET`: トレースデータの中にオーバーフローパケットが含まれていることによる失敗
        * `LIBCSDEC_ERROR_TRACE_DATA_INCOMPLETE`: トレースデータが途中で途切れていることによる失敗
        * `LIBCSDEC_ERROR_PAGE_FAULT`: メモリマップ上に存在しないアドレスをトレースすることによる失敗
