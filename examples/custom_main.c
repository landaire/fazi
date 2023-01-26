#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <assert.h>
#include <time.h>
#define _GNU_SOURCE
#include <unistd.h>

#if __GLIBC__ == 2 && __GLIBC_MINOR__ < 30
#include <sys/syscall.h>
#define gettid() syscall(SYS_gettid)
#endif

// from repo root dir, Test with...
// mkdir corpus
// mkdir crashes
// cargo build --no-default-features
// export LD_LIBRARY_PATH=target/debug
// clang examples/custom_main.c -g -fsanitize=fuzzer-no-link -fsanitize=address -l:libfazi.a -fsanitize-coverage=trace-pc -fsanitize-coverage=trace-pc-guard -Ltarget/debug
// ./a.out

void fazi_start_iteration(char** data, size_t* size);
void fazi_end_iteration(bool need_more_data);
void fazi_initialize();
void fazi_init_signal_handler();
void fazi_set_corpus_dir(const char*);
void fazi_set_crashes_dir(const char*);
void fazi_add_coverage_thread(uint64_t);
void fazi_enable_rust_backtrace();
void fazi_set_max_input_len(int);
void fazi_set_corpus_dir(const char *);
void fazi_set_crashes_dir(const char *);
void fazi_disable_cov_counters();
void fazi_reset_coverage();
void fazi_next_recoverage_testcase(char** data, size_t* size);
void fazi_restore_inputs();

char answer[] = {0xde, 0xad, 0xbe, 0xef};

int no_op_state = 0;

int test_func(const char *data, size_t len) {
    if (memcmp(answer, data, sizeof(answer)) == 0) {
        printf("data matched!\n");
        // artificially crash program
        char *p = 0x13371337;
        *p = 0xff;
        return 1;
    }
    return 0;
}

// Function is used here to help measure fuzzing iterations/s
int test_func_for_perf_measurement(const char *data, size_t len) {
    uint8_t val = (uint8_t)data[0];

    no_op_state += val;
    if (no_op_state == 123456789) {
        printf("wow lucky\n");
    }
    switch (val) {
        case 1:
            no_op_state += 4;
            break;
        case 2:
            no_op_state += 2;
            break;
        case 3:
            no_op_state += 8;
            break;
        case 4:
            no_op_state += 99;
            break;
    }
    return 0;
}

__attribute__((no_sanitize("coverage")))
int main() {
    clock_t start, end;
    double execution_time;
    // Setup fazi globals
    fazi_initialize();
    fazi_init_signal_handler();
    fazi_restore_inputs();
    fazi_enable_rust_backtrace();
    fazi_set_corpus_dir("corpus");
    fazi_set_crashes_dir("crashes");

    // allow the main thread to record coverage
    fazi_add_coverage_thread(gettid());
    fazi_disable_cov_counters();
    fazi_reset_coverage();

    int iterations = 0;
    bool do_recoverage = true;
    char* data = 0;
    size_t len = 0;
    start = clock();
    while (true) {
        if(do_recoverage) {
            fazi_next_recoverage_testcase(&data, &len);
            if (NULL == data) {
                printf("Done with recoverage\n");
                do_recoverage = false;
                continue;
            }
            printf("Recoverage iteration %d\n", iterations);
        }
        else {
            fazi_start_iteration(&data, &len);
        }

        if(len < sizeof(answer)) {
            if(!do_recoverage) {
                fazi_end_iteration(true);
            }
            continue;
        }
        iterations++;
        if (iterations == 100000) {
            end = clock();
            execution_time = ((double)(end - start))/CLOCKS_PER_SEC;
            printf("100000 iterations in : %fs\n", execution_time);
            start = clock();
            iterations = 0;
        }

        test_func_for_perf_measurement(data, len);
        if(!do_recoverage) {
            fazi_end_iteration(false);
        }
    }
    return 0;
}
