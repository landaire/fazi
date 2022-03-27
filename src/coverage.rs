use std::{collections::BTreeSet, hash::Hasher};

use sha1::{Digest, Sha1};

use crate::{driver::{CONSTANTS, COVERAGE}, exports::fazi_initialize};

extern {
    #[link_name = "llvm.returnaddress"]
    fn return_address(a: i32) -> *const u8;
}

macro_rules! caller_address {
    () => {
        unsafe { return_address(0) as usize }
    };
}

#[derive(Debug, Default)]
pub(crate) struct CoverageMap {
    pub u8cov: BTreeSet<u8>,
    pub u16cov: BTreeSet<u16>,
    pub u32cov: BTreeSet<u32>,
    pub u64cov: BTreeSet<u64>,
}

#[no_mangle]
extern "C" fn __sanitizer_cov_trace_pc_guard(guard: *const u32) {
    fazi_initialize();
    let caller_pc = caller_address!();
    COVERAGE
        .get()
        .expect("failed to get COVERAGE")
        .lock()
        .expect("failed to lock COVERAGE")
        .insert(caller_pc);
    //   fuzzer::WarnAboutDeprecatedInstrumentation(
    //       "-fsanitize-coverage=trace-pc-guard");
}

#[no_mangle]
extern "C" fn __sanitizer_cov_trace_pc() {
    let caller_pc = caller_address!();
    COVERAGE
        .get()
        .expect("failed to get COVERAGE")
        .lock()
        .expect("failed to lock COVERAGE")
        .insert(caller_pc);
    //   fuzzer::WarnAboutDeprecatedInstrumentation("-fsanitize-coverage=trace-pc");
}

#[no_mangle]
extern "C" fn __sanitizer_cov_trace_pc_guard_init(start: *const u32, stop: *const u32) {
    fazi_initialize();
    //   fuzzer::WarnAboutDeprecatedInstrumentation(
    //       "-fsanitize-coverage=trace-pc-guard");
}

#[no_mangle]
extern "C" fn __sanitizer_cov_8bit_counters_init(start: *const u32, stop: *const u32) {
    fazi_initialize();
    // println!("init");
    // todo!()
    //   fuzzer::TPC.HandleInline8bitCountersInit(Start, Stop);
}

#[no_mangle]
extern "C" fn __sanitizer_cov_pcs_init(
    pcs_beg: *const std::ffi::c_void,
    pcs_end: *const std::ffi::c_void,
) {
    fazi_initialize();

    // println!("{pcs_beg:p}, {pcs_end:p}");
    // todo!()
    //   fuzzer::TPC.HandlePCsInit(pcs_beg, pcs_end);
}

#[no_mangle]
extern "C" fn __sanitizer_cov_trace_pc_indir(callee: *const std::ffi::c_void) {
    let caller_pc = caller_address!();
    COVERAGE
        .get()
        .expect("failed to get COVERAGE")
        .lock()
        .expect("failed to lock COVERAGE")
        .insert(caller_pc);

    //   uintptr_t PC = reinterpret_cast<uintptr_t>(GET_CALLER_PC());
    //   fuzzer::TPC.HandleCallerCallee(PC, Callee);
}

#[no_mangle]
extern "C" fn __sanitizer_cov_trace_cmp8(arg1: u64, arg2: u64) {
    let caller_pc = caller_address!();
    COVERAGE
        .get()
        .expect("failed to get COVERAGE")
        .lock()
        .expect("failed to lock COVERAGE")
        .insert(caller_pc);

    //   uintptr_t PC = reinterpret_cast<uintptr_t>(GET_CALLER_PC());
    //   fuzzer::TPC.HandleCmp(PC, Arg1, Arg2);
}

// Now the __sanitizer_cov_trace_const_cmp[1248] callbacks just mimic
// the behaviour of __sanitizer_cov_trace_cmp[1248] ones. This, however,
// should be changed later to make full use of instrumentation.
#[no_mangle]
extern "C" fn __sanitizer_cov_trace_const_cmp8(arg1: u64, arg2: u64) {
    let constants = CONSTANTS.get().expect("constants global not initialized");
    let mut constants = constants.lock().expect("failed to lock CONSTANTS global");

    if arg1 <= u8::MAX.try_into().unwrap() {
        constants.u8cov.insert(
            arg1.try_into()
                .expect("cmp4 with argument greater than 8 bits?"),
        );
    }

    if arg1 <= u16::MAX.try_into().unwrap() {
        constants.u16cov.insert(
            arg1.try_into()
                .expect("cmp4 with argument greater than 16 bits?"),
        );
    }

    if arg1 <= u32::MAX.try_into().unwrap() {
        constants.u32cov.insert(
            arg1.try_into()
                .expect("cmp4 with argument greater than 32 bits?"),
        );
    }

    constants.u64cov.insert(
        arg1.try_into()
            .expect("cmp4 with argument greater than 64 bits?"),
    );

    let caller_pc = caller_address!();
    COVERAGE
        .get()
        .expect("failed to get COVERAGE")
        .lock()
        .expect("failed to lock COVERAGE")
        .insert(caller_pc);

    // todo!()
    //   uintptr_t PC = reinterpret_cast<uintptr_t>(GET_CALLER_PC());
    //   fuzzer::TPC.HandleCmp(PC, Arg1, Arg2);
}

#[no_mangle]
extern "C" fn __sanitizer_cov_trace_cmp4(arg1: u32, arg2: u32) {
    let caller_pc = caller_address!();
    COVERAGE
        .get()
        .expect("failed to get COVERAGE")
        .lock()
        .expect("failed to lock COVERAGE")
        .insert(caller_pc);

    // todo!()
    //   uintptr_t PC = reinterpret_cast<uintptr_t>(GET_CALLER_PC());
    //   fuzzer::TPC.HandleCmp(PC, Arg1, Arg2);
}

#[no_mangle]
extern "C" fn __sanitizer_cov_trace_const_cmp4(arg1: u32, arg2: u32) {
    let constants = CONSTANTS.get().expect("constants global not initialized");
    let mut constants = constants.lock().expect("failed to lock CONSTANTS global");
    // Insert into all tables at least 32 bits in size if this number fits
    if arg1 <= u8::MAX.try_into().unwrap() {
        constants.u8cov.insert(
            arg1.try_into()
                .expect("cmp4 with argument greater than 8 bits?"),
        );
    }

    if arg1 <= u16::MAX.try_into().unwrap() {
        constants.u16cov.insert(
            arg1.try_into()
                .expect("cmp4 with argument greater than 8 bits?"),
        );
    }

    constants.u32cov.insert(
        arg1.try_into()
            .expect("cmp4 with argument greater than 8 bits?"),
    );

    let caller_pc = caller_address!();
    COVERAGE
        .get()
        .expect("failed to get COVERAGE")
        .lock()
        .expect("failed to lock COVERAGE")
        .insert(caller_pc);

    //   uintptr_t PC = reinterpret_cast<uintptr_t>(GET_CALLER_PC());
    //   fuzzer::TPC.HandleCmp(PC, Arg1, Arg2);
}

#[no_mangle]
extern "C" fn __sanitizer_cov_trace_cmp2(arg1: u16, arg2: u16) {
    let caller_pc = caller_address!();
    COVERAGE
        .get()
        .expect("failed to get COVERAGE")
        .lock()
        .expect("failed to lock COVERAGE")
        .insert(caller_pc);

    //   uintptr_t PC = reinterpret_cast<uintptr_t>(GET_CALLER_PC());
    //   fuzzer::TPC.HandleCmp(PC, Arg1, Arg2);
}

#[no_mangle]
extern "C" fn __sanitizer_cov_trace_const_cmp2(arg1: u16, arg2: u16) {
    let constants = CONSTANTS.get().expect("constants global not initialized");
    let mut constants = constants.lock().expect("failed to lock CONSTANTS global");
    // Insert into all tables at least 32 bits in size if this number fits
    if arg1 <= u8::MAX.try_into().unwrap() {
        constants.u8cov.insert(
            arg1.try_into()
                .expect("cmp4 with argument greater than 8 bits?"),
        );
    }

    constants.u16cov.insert(
        arg1.try_into()
            .expect("cmp4 with argument greater than 8 bits?"),
    );

    let caller_pc = caller_address!();
    COVERAGE
        .get()
        .expect("failed to get COVERAGE")
        .lock()
        .expect("failed to lock COVERAGE")
        .insert(caller_pc);

    //   uintptr_t PC = reinterpret_cast<uintptr_t>(GET_CALLER_PC());
    //   fuzzer::TPC.HandleCmp(PC, Arg1, Arg2);
}

#[no_mangle]
extern "C" fn __sanitizer_cov_trace_cmp1(arg1: u8, arg2: u8) {
    let caller_pc = caller_address!();
    COVERAGE
        .get()
        .expect("failed to get COVERAGE")
        .lock()
        .expect("failed to lock COVERAGE")
        .insert(caller_pc);

    //   uintptr_t PC = reinterpret_cast<uintptr_t>(GET_CALLER_PC());
    //   fuzzer::TPC.HandleCmp(PC, Arg1, Arg2);
}

#[no_mangle]
extern "C" fn __sanitizer_cov_trace_const_cmp1(arg1: u8, arg2: u8) {
    let constants = CONSTANTS.get().expect("constants global not initialized");
    let mut constants = constants.lock().expect("failed to lock CONSTANTS global");
    // Insert into all tables at least 32 bits in size if this number fits
    constants.u8cov.insert(
        arg1.try_into()
            .expect("cmp4 with argument greater than 8 bits?"),
    );

    let caller_pc = caller_address!();
    COVERAGE
        .get()
        .expect("failed to get COVERAGE")
        .lock()
        .expect("failed to lock COVERAGE")
        .insert(caller_pc);

    //   uintptr_t PC = reinterpret_cast<uintptr_t>(GET_CALLER_PC());
    //   fuzzer::TPC.HandleCmp(PC, Arg1, Arg2);
}

#[no_mangle]
extern "C" fn __sanitizer_cov_trace_switch(val: u64, cases: *const u64) {
    //   uint64_t N = Cases[0];
    //   uint64_t ValSizeInBits = Cases[1];
    //   uint64_t *Vals = Cases + 2;
    //   // Skip the most common and the most boring case: all switch values are small.
    //   // We may want to skip this at compile-time, but it will make the
    //   // instrumentation less general.
    //   if (Vals[N - 1]  < 256)
    //     return;
    //   // Also skip small inputs values, they won't give good signal.
    //   if (Val < 256)
    //     return;
    //   uintptr_t PC = reinterpret_cast<uintptr_t>(GET_CALLER_PC());
    //   size_t i;
    //   uint64_t Smaller = 0;
    //   uint64_t Larger = ~(uint64_t)0;
    //   // Find two switch values such that Smaller < Val < Larger.
    //   // Use 0 and 0xfff..f as the defaults.
    //   for (i = 0; i < N; i++) {
    //     if (Val < Vals[i]) {
    //       Larger = Vals[i];
    //       break;
    //     }
    //     if (Val > Vals[i]) Smaller = Vals[i];
    //   }

    //   // Apply HandleCmp to {Val,Smaller} and {Val, Larger},
    //   // use i as the PC modifier for HandleCmp.
    //   if (ValSizeInBits == 16) {
    //     fuzzer::TPC.HandleCmp(PC + 2 * i, static_cast<uint16_t>(Val),
    //                           (uint16_t)(Smaller));
    //     fuzzer::TPC.HandleCmp(PC + 2 * i + 1, static_cast<uint16_t>(Val),
    //                           (uint16_t)(Larger));
    //   } else if (ValSizeInBits == 32) {
    //     fuzzer::TPC.HandleCmp(PC + 2 * i, static_cast<uint32_t>(Val),
    //                           (uint32_t)(Smaller));
    //     fuzzer::TPC.HandleCmp(PC + 2 * i + 1, static_cast<uint32_t>(Val),
    //                           (uint32_t)(Larger));
    //   } else {
    //     fuzzer::TPC.HandleCmp(PC + 2*i, Val, Smaller);
    //     fuzzer::TPC.HandleCmp(PC + 2*i + 1, Val, Larger);
    //   }
}

#[no_mangle]
extern "C" fn __sanitizer_cov_trace_div4(val: u32) {
    let caller_pc = caller_address!();
    COVERAGE
        .get()
        .expect("failed to get COVERAGE")
        .lock()
        .expect("failed to lock COVERAGE")
        .insert(caller_pc);
    //   uintptr_t PC = reinterpret_cast<uintptr_t>(GET_CALLER_PC());
    //   fuzzer::TPC.HandleCmp(PC, Val, (uint32_t)0);
}

#[no_mangle]
extern "C" fn __sanitizer_cov_trace_div8(val: u64) {
    let caller_pc = caller_address!();
    COVERAGE
        .get()
        .expect("failed to get COVERAGE")
        .lock()
        .expect("failed to lock COVERAGE")
        .insert(caller_pc);
    //   uintptr_t PC = reinterpret_cast<uintptr_t>(GET_CALLER_PC());
    //   fuzzer::TPC.HandleCmp(PC, Val, (uint64_t)0);
}

#[no_mangle]
extern "C" fn __sanitizer_cov_trace_gep(idx: *const std::ffi::c_void) {
    let caller_pc = caller_address!();
    COVERAGE
        .get()
        .expect("failed to get COVERAGE")
        .lock()
        .expect("failed to lock COVERAGE")
        .insert(caller_pc);

    //   uintptr_t PC = reinterpret_cast<uintptr_t>(GET_CALLER_PC());
    //   fuzzer::TPC.HandleCmp(PC, Idx, (uintptr_t)0);
}

#[no_mangle]
extern "C" fn __sanitizer_weak_hook_memcmp(
    caller_pc: *const std::ffi::c_void,
    s1: *const std::ffi::c_void,
    s2: *const std::ffi::c_void,
    n: usize,
    result: std::os::raw::c_int,
) {
    let caller_pc = caller_address!();
    COVERAGE
        .get()
        .expect("failed to get COVERAGE")
        .lock()
        .expect("failed to lock COVERAGE")
        .insert(caller_pc);
    //   if (!fuzzer::RunningUserCallback) return;
    //   if (result == 0) return;  // No reason to mutate.
    //   if (n <= 1) return;  // Not interesting.
    //   fuzzer::TPC.AddValueForMemcmp(caller_pc, s1, s2, n, /*StopAtZero*/false);
}

#[no_mangle]
extern "C" fn __sanitizer_weak_hook_strncmp(
    caller_pc: *const std::ffi::c_void,
    s1: *const std::ffi::c_void,
    s2: *const std::ffi::c_void,
    n: usize,
    result: std::os::raw::c_int,
) {
    let caller_pc = caller_address!();
    COVERAGE
        .get()
        .expect("failed to get COVERAGE")
        .lock()
        .expect("failed to lock COVERAGE")
        .insert(caller_pc);
    //   if (!fuzzer::RunningUserCallback) return;
    //   if (result == 0) return;  // No reason to mutate.
    //   size_t Len1 = fuzzer::InternalStrnlen(s1, n);
    //   size_t Len2 = fuzzer::InternalStrnlen(s2, n);
    //   n = std::min(n, Len1);
    //   n = std::min(n, Len2);
    //   if (n <= 1) return;  // Not interesting.
    //   fuzzer::TPC.AddValueForMemcmp(caller_pc, s1, s2, n, /*StopAtZero*/true);
}

#[no_mangle]
extern "C" fn __sanitizer_weak_hook_strcmp(
    caller_pc: *const std::ffi::c_void,
    s1: *const std::ffi::c_void,
    s2: *const std::ffi::c_void,
    result: std::os::raw::c_int,
) {
    let caller_pc = caller_address!();
    COVERAGE
        .get()
        .expect("failed to get COVERAGE")
        .lock()
        .expect("failed to lock COVERAGE")
        .insert(caller_pc);
    //   if (!fuzzer::RunningUserCallback) return;
    //   if (result == 0) return;  // No reason to mutate.
    //   size_t N = fuzzer::InternalStrnlen2(s1, s2);
    //   if (N <= 1) return;  // Not interesting.
    //   fuzzer::TPC.AddValueForMemcmp(caller_pc, s1, s2, N, /*StopAtZero*/true);
}

#[no_mangle]
extern "C" fn __sanitizer_weak_hook_strncasecmp(
    caller_pc: *const std::ffi::c_void,
    s1: *const std::ffi::c_void,
    s2: *const std::ffi::c_void,
    n: usize,
    result: std::os::raw::c_int,
) {
    let caller_pc = caller_address!();
    COVERAGE
        .get()
        .expect("failed to get COVERAGE")
        .lock()
        .expect("failed to lock COVERAGE")
        .insert(caller_pc);

    //   if (!fuzzer::RunningUserCallback) return;
    //   return __sanitizer_weak_hook_strncmp(called_pc, s1, s2, n, result);
}

#[no_mangle]
extern "C" fn __sanitizer_weak_hook_strcasecmp(
    caller_pc: *const std::ffi::c_void,
    s1: *const std::ffi::c_void,
    s2: *const std::ffi::c_void,
    result: std::os::raw::c_int,
) {
    let caller_pc = caller_address!();
    COVERAGE
        .get()
        .expect("failed to get COVERAGE")
        .lock()
        .expect("failed to lock COVERAGE")
        .insert(caller_pc);
    //   if (!fuzzer::RunningUserCallback) return;
    //   return __sanitizer_weak_hook_strcmp(called_pc, s1, s2, result);
}

#[no_mangle]
extern "C" fn __sanitizer_weak_hook_strstr(
    caller_pc: *const std::ffi::c_void,
    s1: *const std::ffi::c_void,
    s2: *const std::ffi::c_void,
    result: std::os::raw::c_int,
) {
    let caller_pc = caller_address!();
    COVERAGE
        .get()
        .expect("failed to get COVERAGE")
        .lock()
        .expect("failed to lock COVERAGE")
        .insert(caller_pc);
    //   if (!fuzzer::RunningUserCallback) return;
    //   fuzzer::TPC.MMT.Add(reinterpret_cast<const uint8_t *>(s2), strlen(s2));
}

#[no_mangle]
extern "C" fn __sanitizer_weak_hook_strcasestr(
    caller_pc: *const std::ffi::c_void,
    s1: *const std::ffi::c_void,
    s2: *const std::ffi::c_void,
    result: std::os::raw::c_int,
) {
    let caller_pc = caller_address!();
    COVERAGE
        .get()
        .expect("failed to get COVERAGE")
        .lock()
        .expect("failed to lock COVERAGE")
        .insert(caller_pc);
    //   if (!fuzzer::RunningUserCallback) return;
    //   fuzzer::TPC.MMT.Add(reinterpret_cast<const uint8_t *>(s2), strlen(s2));
}

#[no_mangle]
extern "C" fn __sanitizer_weak_hook_memmem(
    caller_pc: *const std::ffi::c_void,
    s1: *const std::ffi::c_void,
    len1: usize,
    s2: *const std::ffi::c_void,
    len2: usize,
    result: std::os::raw::c_int,
) {
    let caller_pc = caller_address!();
    COVERAGE
        .get()
        .expect("failed to get COVERAGE")
        .lock()
        .expect("failed to lock COVERAGE")
        .insert(caller_pc);
    //   if (!fuzzer::RunningUserCallback) return;
    //   fuzzer::TPC.MMT.Add(reinterpret_cast<const uint8_t *>(s2), len2);
}