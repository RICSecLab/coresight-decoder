# coresight-decoder
Experimental CoreSight Decoder


## ライブラリの使い方
### AFL-like
AFLと同じbitmapの計算方法を用いる。バイナリファイルとトレースデータからエッジカバレッジを復元し、その情報からbitmapを計算する。そのため、バイナリファイルが必要である。
```c
const int bitmap_size = 0x1000;
unsigned char* bitmap = (unsigned char*)malloc(bitmap_size);

// 永続的に使われるデータを初期化する。
libcsdec_t libcsdec = libcsdec_init(bitmap, bitmap_size);

const char trace_id = 0x10;
const int memory_map_num = 3;
const struct libcsdec_memory_map memory_map[] = {
    {0xaaaadd370000, 0xaaaadd371000, "fib"},
    {0xffff9d470000, 0xffff9d491000, "ld-2.31.so"},
    {0xffff9d2fd000, 0xffff9d470000, "libc-2.31.so"}
};


// デコードに必要な状態をリセットする。
libcsdec_reset_process(libcsdec, trace_id, memory_map_num, memory_map);

// 逐次的にデコードを行う。
// もちろん、1度に全体のトレースデータを渡して、
// 1度の実行でデコードを終わらせることもできる。
while (trace(trace_data_addr, trace_data_size)) {
    if (libcsdec_run_process(libcsdec, trace_data_addr, trace_data_size)
        != LIBCEDEC_SUCCESS) {
        exit(EXIT_FAILURE);
    }
}

// デコードに必要な処理を追加する
if (libcsdec_finish_process(libcsdec) != LIBCEDEC_SUCCESS) {
    exit(EXIT_FAILURE);
}
```

### PTrix-like
バイナリファイルの情報を用いず、トレースデータのみを用いてビットマップを計算する。そのため、バイナリファイルのディスアセンブルが不要になり、AFL-likeなビットマップの計算より高速に動く。
```c
const int bitmap_size = 0x1000;
unsigned char* bitmap = (unsigned char*)malloc(bitmap_size);

// 永続的に使われるデータを初期化する。
libcsdec_t libcsdec = libcsdec_init_ptrix_process(
    bitmap, bitmap_size);

const char trace_id = 0x10;
const int memory_map_num = 3;
const struct libcsdec_memory_map memory_map[] = {
    {0xaaaadd370000, 0xaaaadd371000, "fib"},
    {0xffff9d470000, 0xffff9d491000, "ld-2.31.so"},
    {0xffff9d2fd000, 0xffff9d470000, "libc-2.31.so"}
};


// デコードに必要な状態をリセットする。
libcsdec_reset_ptrix_process(libcsdec, trace_id, memory_map_num, memory_map);

// 逐次的にデコードを行う。
// もちろん、1度に全体のトレースデータを渡して、
// 1度の実行でデコードを終わらせることもできる。
while (trace(trace_data_addr, trace_data_size)) {
    if (libcsdec_run_ptrix_process(libcsdec, trace_data_addr, trace_data_size)
        != LIBCEDEC_SUCCESS) {
        exit(EXIT_FAILURE);
    }
}

// デコードに必要な処理を追加する
if (libcsdec_finish_ptrix_process(libcsdec) != LIBCEDEC_SUCCESS) {
    exit(EXIT_FAILURE);
}
```

## ライブラリのインターフェース
### AFL-like
#### libcsdec_init()
```c
libcsdec_t libcsdec_init(
    void *bitmap_addr, int bitmap_size);
```

永続的時利用するオブジェクトを初期化し、そのオブジェクトのポインタを返す。

* 引数:
    * `bitmap_addr`: ビットマップを書き込む先頭アドレス
    * `bitmap_size`: ビットマップのサイズ
* 戻り値:
    * libcsdec内で使うオブジェクトのポインタ

#### libcsdec_reset_process()
```c
libcsdec_result_t libcsdec_reset_process(
    const libcsdec_t libcsdec,
    char trace_id, int memory_map_num,
    const struct libcsdec_memory_map libcsdec_memory_map[]);
```

各トレースのデコード開始時に、必要な状態を初期化する。

* 引数:
    * `libcsdec`: libcsdec_init()の戻り値
    * `trace_id`: トレースID
    * `memory_map_num`: メモリマップの数
    * `libcsdec_memory_map`: トレースを行ったプロセスのメモリマップ（すべての実行領域の情報が必要）
        * `libcsdec_memory_map::start`:　マップされている開始アドレス
        * `libcsdec_memory_map::end`:  マップされている終了アドレス
        * `libcsdec_memory_map::path`: マップされてているバイナリファイルのパス
* 戻り値:
    * `libcsdec_result_t` 実行が正解したかどうかの情報
        * `LIBCEDEC_SUCCESS`: 実行成功
        * `LIBCSDEC_ERROR`: 実行失敗（不正なメモリマップ情報）

#### libcsdec_run_process()
```c
libcsdec_result_t libcsdec_run_process(
    const libcsdec_t libcsdec,
    const void *trace_data_addr, std::size_t trace_data_size);
```

トレースデータとlibcsdec_init()で登録したバイナリファイルから、エッジカバレッジを計算し、ビットマップに書き込む。
トレースデータは断片的なものでよく、逐次的にトレースデータを渡し、デコードを進めることができる。

* 引数:
    * `libcsdec`: トレースを行うバイナリファイルの数
    * `trace_data_addr`: トレースデータが書き込まれているアドレス（ライブラリはこの領域を読むだけ）
    * `trace_data_size`: トレースデータのサイズ

* 戻り値:
    * `libcsdec_result_t` 実行が正解したかどうかの情報
        * `LIBCEDEC_SUCCESS`: 実行成功
        * `LIBCSDEC_ERROR`: 実行失敗
        * `LIBCSDEC_ERROR_OVERFLOW_PACKET`: トレースデータの中にオーバーフローパケットが含まれていることによる失敗
        * `LIBCSDEC_ERROR_TRACE_DATA_INCOMPLETE`: トレースデータが途中で途切れていることによる失敗
        * `LIBCSDEC_ERROR_PAGE_FAULT`: メモリマップ上に存在しないアドレスをトレースすることによる失敗

#### libcsdec_finish_process()
```c
libcsdec_result_t libcsdec_finish_process(const libcsdec_t libcsdec);
```

各トレースのデコード終了時に、デコードが不正な状態で終わっていないかをチェックする。

* 引数:
    * `libcsdec`: トレースを行うバイナリファイルの数

* 戻り値:
    * `libcsdec_result_t` 実行が正解したかどうかの情報
        * `LIBCEDEC_SUCCESS`: 実行成功
        * `LIBCSDEC_ERROR_TRACE_DATA_INCOMPLETE`: トレースデータが途中で途切れていることによる失敗

### PTrix-like
#### libcsdec_init_ptrix_process
```c
libcsdec_t libcsdec_init_ptrix_process(
    void *bitmap_addr, int bitmap_size);
```

永続的時利用するオブジェクトを初期化し、そのオブジェクトのポインタを返す。

* 引数:
    * `bitmap_addr`: ビットマップを書き込む先頭アドレス
    * `bitmap_size`: ビットマップのサイズ
* 戻り値:
    * libcsdec内で使うオブジェクトのポインタ

#### libcsdec_reset_process()
```c

libcsdec_result_t libcsdec_reset_ptrix_process(
    const libcsdec_t libcsdec,
    char trace_id, int memory_map_num,
    const struct libcsdec_memory_map libcsdec_memory_map[]);
```

各トレースのデコード開始時に、必要な状態を初期化する。

* 引数:
    * `libcsdec`: libcsdec_init()の戻り値
    * `trace_id`: トレースID
    * `memory_map_num`: メモリマップの数
    * `libcsdec_memory_map`: トレースを行ったプロセスのメモリマップ（すべての実行領域の情報が必要）
        * `libcsdec_memory_map::start`:　マップされている開始アドレス
        * `libcsdec_memory_map::end`:  マップされている終了アドレス
        * `libcsdec_memory_map::path`: マップされてているバイナリファイルのパス
* 戻り値:
    * `libcsdec_result_t` 実行が正解したかどうかの情報
        * `LIBCEDEC_SUCCESS`: 実行成功
        * `LIBCSDEC_ERROR`: 実行失敗（不正なメモリマップ情報）

#### libcsdec_run_process()
```c
libcsdec_result_t libcsdec_run_ptrix_process(
    const libcsdec_t libcsdec,
    const void *trace_data_addr, const size_t trace_data_size);
```

トレースデータとlibcsdec_init()で登録したバイナリファイルから、エッジカバレッジを計算し、ビットマップに書き込む。
トレースデータは断片的なものでよく、逐次的にトレースデータを渡し、デコードを進めることができる。

* 引数:
    * `libcsdec`: トレースを行うバイナリファイルの数
    * `trace_data_addr`: トレースデータが書き込まれているアドレス（ライブラリはこの領域を読むだけ）
    * `trace_data_size`: トレースデータのサイズ

* 戻り値:
    * `libcsdec_result_t` 実行が正解したかどうかの情報
        * `LIBCEDEC_SUCCESS`: 実行成功
        * `LIBCSDEC_ERROR`: 実行失敗
        * `LIBCSDEC_ERROR_OVERFLOW_PACKET`: トレースデータの中にオーバーフローパケットが含まれていることによる失敗
        * `LIBCSDEC_ERROR_TRACE_DATA_INCOMPLETE`: トレースデータが途中で途切れていることによる失敗
        * `LIBCSDEC_ERROR_PAGE_FAULT`: メモリマップ上に存在しないアドレスをトレースすることによる失敗

#### libcsdec_finish_process()
```c
libcsdec_result_t libcsdec_finish_ptrix_process(const libcsdec_t libcsdec);
```

各トレースのデコード終了時に、デコードが不正な状態で終わっていないかをチェックする。

* 引数:
    * `libcsdec`: トレースを行うバイナリファイルの数

* 戻り値:
    * `libcsdec_result_t` 実行が正解したかどうかの情報
        * `LIBCEDEC_SUCCESS`: 実行成功
