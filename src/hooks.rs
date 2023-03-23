use crate::sancov::{caller_address, return_address};
use std::ffi::CString;
use std::os::raw::c_int;

use crate::sancov::__sanitizer_weak_hook_memcmp;
use libc::c_void;
use once_cell::sync::OnceCell;

type MemCmpFn = unsafe extern "C" fn(*const libc::c_char, *const libc::c_char, usize) -> c_int;
static MEMCMP_ADDRESS: OnceCell<MemCmpFn> = OnceCell::new();

// libc for android doesn't define this for android yet
// bionic defines this here https://github.com/aosp-mirror/platform_bionic/blob/master/libc/include/dlfcn.h
#[cfg(all(target_os = "android", target_pointer_width = "64"))]
const RTLD_NEXT: *mut c_void = -1i64 as *mut c_void;
#[cfg(all(target_os = "android", not(target_pointer_width = "64")))]
const RTLD_NEXT: *mut c_void = 0xfffffffe as *mut c_void;

#[cfg(not(target_os = "android"))]
use libc::RTLD_NEXT;

#[no_mangle]
#[cfg(feature = "hook_memcmp")]
extern "C" fn memcmp(s1: *const libc::c_char, s2: *const libc::c_char, count: usize) -> c_int {
    let caller_pc = caller_address!();
    let real_memcmp = match MEMCMP_ADDRESS.get() {
        Some(&real_memcmp) => real_memcmp,
        None => {
            // We can fail to set `MEMCMP_ADDRESS` if another thread did a memcmp() at the same time.
            // It's fine if this has been done.
            let symbol_name = CString::new("memcmp").unwrap();
            let fn_address =
                unsafe { libc::dlsym(RTLD_NEXT, symbol_name.as_ptr()) as *const c_void };
            let real_memcmp = unsafe { std::mem::transmute::<_, MemCmpFn>(fn_address) };
            let _ = MEMCMP_ADDRESS.set(real_memcmp);
            real_memcmp
        }
    };

    let result = unsafe { (real_memcmp)(s1, s2, count) };
    __sanitizer_weak_hook_memcmp(caller_pc, s1, s2, count, result);

    result
}

#[no_mangle]
#[cfg(feature = "hook_bcmp")]
extern "C" fn bcmp(s1: *const libc::c_char, s2: *const libc::c_char, count: usize) -> c_int {
    let caller_pc = caller_address!();
    let real_memcmp = match MEMCMP_ADDRESS.get() {
        Some(&real_memcmp) => real_memcmp,
        None => {
            // We can fail to set `MEMCMP_ADDRESS` if another thread did a memcmp() at the same time.
            // It's fine if this has been done.
            let symbol_name = CString::new("memcmp").unwrap();
            let fn_address =
                unsafe { libc::dlsym(RTLD_NEXT, symbol_name.as_ptr()) as *const c_void };
            let real_memcmp = unsafe { std::mem::transmute::<_, MemCmpFn>(fn_address) };
            let _ = MEMCMP_ADDRESS.set(real_memcmp);
            real_memcmp
        }
    };

    let result = unsafe { (real_memcmp)(s1, s2, count) };
    __sanitizer_weak_hook_memcmp(caller_pc, s1, s2, count, result);

    result
}

// #[no_mangle]
// extern "C" fn strncmp(
//     caller_pc: *const std::ffi::c_void,
//     _s1: *const std::ffi::c_void,
//     _s2: *const std::ffi::c_void,
//     _n: usize,
//     _result: std::os::raw::c_int,
// ) {
//     let caller_pc = caller_pc as usize;
//     TESTCASE_COVERAGE
//         .get()
//         .expect("failed to get TESTCASE_COVERAGE")
//         .lock()
//         .expect("failed to lock TESTCASE_COVERAGE")
//         .insert(caller_pc);
//     //   if (!fuzzer::RunningUserCallback) return;
//     //   if (result == 0) return;  // No reason to mutate.
//     //   size_t Len1 = fuzzer::InternalStrnlen(s1, n);
//     //   size_t Len2 = fuzzer::InternalStrnlen(s2, n);
//     //   n = std::min(n, Len1);
//     //   n = std::min(n, Len2);
//     //   if (n <= 1) return;  // Not interesting.
//     //   fuzzer::TPC.AddValueForMemcmp(caller_pc, s1, s2, n, /*StopAtZero*/true);
// }

// #[no_mangle]
// extern "C" fn __sanitizer_weak_hook_strcmp(
//     caller_pc: *const std::ffi::c_void,
//     s1: *const libc::c_char,
//     s2: *const libc::c_char,
//     result: std::os::raw::c_int,
// ) {
//     __sanitizer_weak_hook_memcmp(caller_pc, s1, s2, strlen2(s1, s2), result)
//     //   if (!fuzzer::RunningUserCallback) return;
//     //   if (result == 0) return;  // No reason to mutate.
//     //   size_t N = fuzzer::InternalStrnlen2(s1, s2);
//     //   if (N <= 1) return;  // Not interesting.
//     //   fuzzer::TPC.AddValueForMemcmp(caller_pc, s1, s2, N, /*StopAtZero*/true);
// }

// #[no_mangle]
// extern "C" fn __sanitizer_weak_hook_strncasecmp(
//     caller_pc: *const std::ffi::c_void,
//     _s1: *const std::ffi::c_void,
//     _s2: *const std::ffi::c_void,
//     _n: usize,
//     _result: std::os::raw::c_int,
// ) {
//     let caller_pc = caller_pc as usize;
//     TESTCASE_COVERAGE
//         .get()
//         .expect("failed to get TESTCASE_COVERAGE")
//         .lock()
//         .expect("failed to lock TESTCASE_COVERAGE")
//         .insert(caller_pc);

//     //   if (!fuzzer::RunningUserCallback) return;
//     //   return __sanitizer_weak_hook_strncmp(called_pc, s1, s2, n, result);
// }

// #[no_mangle]
// extern "C" fn __sanitizer_weak_hook_strcasecmp(
//     _caller_pc: *const std::ffi::c_void,
//     _s1: *const std::ffi::c_void,
//     _s2: *const std::ffi::c_void,
//     _result: std::os::raw::c_int,
// ) {
//     let caller_pc = caller_address!();
//     TESTCASE_COVERAGE
//         .get()
//         .expect("failed to get TESTCASE_COVERAGE")
//         .lock()
//         .expect("failed to lock TESTCASE_COVERAGE")
//         .insert(caller_pc);
//     //   if (!fuzzer::RunningUserCallback) return;
//     //   return __sanitizer_weak_hook_strcmp(called_pc, s1, s2, result);
// }

// #[no_mangle]
// extern "C" fn __sanitizer_weak_hook_strstr(
//     caller_pc: *const std::ffi::c_void,
//     _s1: *const std::ffi::c_void,
//     _s2: *const std::ffi::c_void,
//     _result: std::os::raw::c_int,
// ) {
//     let caller_pc = caller_pc as usize;
//     TESTCASE_COVERAGE
//         .get()
//         .expect("failed to get TESTCASE_COVERAGE")
//         .lock()
//         .expect("failed to lock TESTCASE_COVERAGE")
//         .insert(caller_pc);
//     //   if (!fuzzer::RunningUserCallback) return;
//     //   fuzzer::TPC.MMT.Add(reinterpret_cast<const uint8_t *>(s2), strlen(s2));
// }

// #[no_mangle]
// extern "C" fn __sanitizer_weak_hook_strcasestr(
//     caller_pc: *const std::ffi::c_void,
//     _s1: *const std::ffi::c_void,
//     _s2: *const std::ffi::c_void,
//     _result: std::os::raw::c_int,
// ) {
//     let caller_pc = caller_pc as usize;
//     TESTCASE_COVERAGE
//         .get()
//         .expect("failed to get TESTCASE_COVERAGE")
//         .lock()
//         .expect("failed to lock TESTCASE_COVERAGE")
//         .insert(caller_pc);
//     //   if (!fuzzer::RunningUserCallback) return;
//     //   fuzzer::TPC.MMT.Add(reinterpret_cast<const uint8_t *>(s2), strlen(s2));
// }

// #[no_mangle]
// extern "C" fn __sanitizer_weak_hook_memmem(
//     caller_pc: *const std::ffi::c_void,
//     _s1: *const std::ffi::c_void,
//     _len1: usize,
//     _s2: *const std::ffi::c_void,
//     _len2: usize,
//     _result: std::os::raw::c_int,
// ) {
//     let caller_pc = caller_pc as usize;
//     TESTCASE_COVERAGE
//         .get()
//         .expect("failed to get TESTCASE_COVERAGE")
//         .lock()
//         .expect("failed to lock TESTCASE_COVERAGE")
//         .insert(caller_pc);
//     //   if (!fuzzer::RunningUserCallback) return;
//     //   fuzzer::TPC.MMT.Add(reinterpret_cast<const uint8_t *>(s2), len2);
// }

// /// Returns the minimum string length of the two arguments
// fn strlen2(s1: *const libc::c_char, s2: *const libc::c_char) -> usize {
//     let mut len = 0;
//     while unsafe { *s1.offset(len) != 0 } && unsafe { *s2.offset(len) != 0 } {
//         len += 1;
//     }

//     return len.try_into().expect("failed to convert len to usze");
// }

use std::ffi;
