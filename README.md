# Fazi

A reimplementation of libfuzzer in Rust

## Usage


Step 1: Build fazi:

```bash
$ cargo build --release
```

Step 2: Build your harness:

```bash
$ clang ./main.c -fsanitize=fuzzer-no-link -fsanitize=address -lfazi -L$FAZI_DIR/target/release/
```

Step 3: Run the harness:

```bash
$ ./a.out
```

You can list command-line options with the `--help` flag:

```
fazi

USAGE:
    a.out [OPTIONS]

OPTIONS:
        --corpus-dir <CORPUS_DIR>                    [default: ./corpus]
        --crashes-dir <CRASHES_DIR>                  [default: ./crashes]
    -h, --help                                       Print help information
        --len-control <LEN_CONTROL>                  [default: 100]
        --max-mutation-depth <MAX_MUTATION_DEPTH>    [default: 15]
        --seed <SEED>
```

## Why

While libfuzzer can be used as a library, engaging with it from some environments may be difficult to setup. Fazi provides
similar functionality to libfuzzer, but gives greater flexibility into how you can use it. For instance, a native application
which requires its own main entry point may be setup like:

```c
/// compiled with -fsanitize=fuzer-no-link

extern "C" int LLVMFuzzerRunDriver(int *argc, char ***argv,
                  int (*UserCb)(const uint8_t *Data, size_t Size));

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    // fuzz
}

int main(int *argc, char ***argv) {
    // Do my own thing
    LLVMFuzzerRunDriver(argc, argv, LLVMFuzzerTestOneInput);
}
```

This model is difficult when integrating into an application with a lot of state or its own runtime environment, such as
the JVM. Instead of providing a callback, Fazi lets you just ask it for data and tell it when the testcase is done:

```c
typedef struct _fazi_input {
    const uint8_t *data;
    size_t len;
} FaziInput;

extern "C" FaziInput fazi_start_testcase();
extern "C" void fazi_end_testcase(bool);
extern "C" void fazi_initialize();
extern "C" void fazi_set_corpus_dir(const char*);
extern "C" void fazi_set_crashes_dir(const char*);

int main() {
    // Setup fazi globals
    fazi_initialize();

    while (true) {
        FaziInput input = fazi_start_testcase();

        bool need_more_data = some_api(input.data, input.len);

        fazi_end_testcase(need_more_data);
    }
}
```