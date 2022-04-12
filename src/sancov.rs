use std::{
    collections::{BTreeSet, HashSet},
    hash::Hasher,
    sync::atomic::AtomicU8,
};

use crate::{
    driver::{COMPARISON_OPERANDS, TESTCASE_COVERAGE, PC_INFO, U8_COUNTERS},
    exports::fazi_initialize,
};

#[derive(Debug)]
#[repr(C)]
pub(crate) struct PcEntry {
    pub pc: usize,
    pub flags: usize,
}

impl PcEntry {
    pub(crate) fn is_fn_entry(&self) -> bool {
        self.flags & 1 != 0
    }
}

extern "C" {
    #[link_name = "llvm.returnaddress"]
    fn return_address(a: i32) -> *const u8;
}

macro_rules! caller_address {
    () => {
        unsafe { return_address(0) as usize }
    };
}

#[derive(Debug, Clone)]
pub(crate) enum CmpOperand<T: Clone> {
    /// Represents a constant value in a comparison operation. e.g. if the x86
    /// assembly is `cmp rax, 10`, we'd want to represent that the right-hand
    /// side of this instruction was a constant value of 10.
    Constant(T),
    /// Represents a constant value in a comparison operation. e.g. if the x86
    /// assembly is `cmp rax, 10`, where `rax` is 5, we'd want to represent that
    /// the left-hand side of this instruction is a dynamic value of 5.
    Dynamic(T),
}

impl<T: Clone> CmpOperand<T> {
    pub fn inner(&self) -> T {
        match self {
            CmpOperand::Constant(val) => val.clone(),
            CmpOperand::Dynamic(val) => val.clone(),
        }
    }

    pub fn inner_ref(&self) -> &T {
        match self {
            CmpOperand::Constant(val) => val,
            CmpOperand::Dynamic(val) => val,
        }
    }

    pub fn is_const(&self) -> bool {
        matches!(self, CmpOperand::Constant(_))
    }

    pub fn is_dynamic(&self) -> bool {
        matches!(self, CmpOperand::Dynamic(_))
    }
}

macro_rules! impl_try_from {
    ($from:ty, $to:ty) => {
        impl TryFrom<CmpOperand<$from>> for CmpOperand<$to> {
            type Error = <$to as TryFrom<$from>>::Error;

            fn try_from(value: CmpOperand<$from>) -> Result<Self, Self::Error> {
                match value {
                    CmpOperand::Constant(val) => Ok(CmpOperand::Constant(val.try_into()?)),
                    CmpOperand::Dynamic(val) => Ok(CmpOperand::Dynamic(val.try_into()?)),
                }
            }
        }
    };
}

impl_try_from!(u64, u8);
impl_try_from!(u64, u16);
impl_try_from!(u64, u32);
impl_try_from!(u32, u64);
impl_try_from!(u32, u16);
impl_try_from!(u32, u8);
impl_try_from!(u16, u32);
impl_try_from!(u16, u64);
impl_try_from!(u16, u8);
impl_try_from!(u8, u16);
impl_try_from!(u8, u32);
impl_try_from!(u8, u64);

impl<T: Eq + Clone> Eq for CmpOperand<T> {}

impl<T: PartialEq + Clone> PartialEq for CmpOperand<T> {
    fn eq(&self, other: &Self) -> bool {
        self.inner_ref() == other.inner_ref()
    }
}

impl<T: PartialOrd + Clone> PartialOrd for CmpOperand<T> {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        self.inner_ref().partial_cmp(other.inner_ref())
    }
}

impl<T: Ord + Clone> Ord for CmpOperand<T> {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.inner_ref().cmp(other.inner_ref())
    }
}

#[derive(Debug, Default)]
pub(crate) struct CoverageMap {
    pub u8cov: BTreeSet<(CmpOperand<u8>, CmpOperand<u8>)>,
    pub u16cov: BTreeSet<(CmpOperand<u16>, CmpOperand<u16>)>,
    pub u32cov: BTreeSet<(CmpOperand<u32>, CmpOperand<u32>)>,
    pub u64cov: BTreeSet<(CmpOperand<u64>, CmpOperand<u64>)>,
    pub binary: HashSet<(Vec<u8>, Vec<u8>)>,
}

impl CoverageMap {
    pub fn clear(&mut self) {
        self.u8cov.clear();
        self.u16cov.clear();
        self.u32cov.clear();
        self.u64cov.clear();
        self.binary.clear();
    }
}

#[no_mangle]
extern "C" fn __sanitizer_cov_trace_pc_guard(_guard: *const u32) {
    fazi_initialize();
    let caller_pc = caller_address!();
    TESTCASE_COVERAGE
        .get()
        .expect("failed to get TESTCASE_COVERAGE")
        .lock()
        .expect("failed to lock TESTCASE_COVERAGE")
        .insert(caller_pc);
    //   fuzzer::WarnAboutDeprecatedInstrumentation(
    //       "-fsanitize-coverage=trace-pc-guard");
}

#[no_mangle]
extern "C" fn __sanitizer_cov_trace_pc() {
    let caller_pc = caller_address!();
    TESTCASE_COVERAGE
        .get()
        .expect("failed to get TESTCASE_COVERAGE")
        .lock()
        .expect("failed to lock TESTCASE_COVERAGE")
        .insert(caller_pc);
    //   fuzzer::WarnAboutDeprecatedInstrumentation("-fsanitize-coverage=trace-pc");
}

#[no_mangle]
extern "C" fn __sanitizer_cov_8bit_counters_init(start: *mut u8, stop: *mut u8) {
    fazi_initialize();

    let mut u8_counters = U8_COUNTERS
        .get()
        .expect("U8_COUNTERS not initialized")
        .lock()
        .expect("failed to lock U8_COUNTERS");

     let counters = unsafe {
            std::slice::from_raw_parts(start as *const AtomicU8, stop as usize - start as usize)
    };

    for other_counters in &*u8_counters {
        if other_counters.as_ptr() == counters.as_ptr() {
            return;
        }
    }
    u8_counters.push(counters);
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
    let mut module_pc_info = PC_INFO.get().expect("PC_INFO not initialize").lock().expect("failed to lock PC_INFO");
    let pc_info = unsafe {
        std::slice::from_raw_parts(
            pcs_beg as *const PcEntry,
            (pcs_end as *const PcEntry).offset_from(pcs_beg as *const PcEntry) as usize,
        )
    };

    for known_pc_info in &*module_pc_info {
        if known_pc_info.as_ptr() == pc_info.as_ptr() {
            return;
        }
    }

    module_pc_info.push(pc_info);
}

#[no_mangle]
extern "C" fn __sanitizer_cov_trace_pc_indir(callee: *const std::ffi::c_void) {
    use std::collections::hash_map::DefaultHasher;

    let caller_pc = caller_address!();
    let mut coverage = TESTCASE_COVERAGE
        .get()
        .expect("failed to get TESTCASE_COVERAGE")
        .lock()
        .expect("failed to lock TESTCASE_COVERAGE");

    let mut s = DefaultHasher::new();
    s.write_usize(callee as usize);
    s.write_usize(caller_pc as usize);
    let hash = s.finish();

    // Insert the caller and callee, then the two combined (edge)
    coverage.insert(caller_pc);
    coverage.insert(callee as usize);
    coverage.insert(hash as usize);

    //   uintptr_t PC = reinterpret_cast<uintptr_t>(GET_CALLER_PC());
    //   fuzzer::TPC.HandleCallerCallee(PC, Callee);
}

macro_rules! handle_cmp {
    ($arg1:expr, $arg2:expr, $ty:ty) => {
        let constants = COMPARISON_OPERANDS
            .get()
            .expect("constants global not initialized");
        let constants = constants
            .try_lock();
        // We may have failed to lock if the Fazi harness locked the code,
        // entered some stdlib code that's instrumented, which calls back
        // into here...
        if constants.is_err() {
            return;
        }
        let mut constants = constants.unwrap();

        let sizeof_type = std::mem::size_of::<$ty>();

        if $arg1.inner() <= u8::MAX.try_into().unwrap()
            && $arg2.inner() <= u8::MAX.try_into().unwrap()
        {
            constants.u8cov.insert((
                $arg1.try_into().expect("failed to convert to cmp args u8"),
                $arg2.try_into().expect("failed to convert to cmp args u8"),
            ));
        }

        if sizeof_type >= 2
            && $arg1.inner() <= u16::MAX.try_into().unwrap()
            && $arg2.inner() <= u16::MAX.try_into().unwrap()
        {
            constants.u16cov.insert((
                $arg1.try_into().expect("failed to convert to cmp args u32"),
                $arg2.try_into().expect("failed to convert to cmp args u32"),
            ));
        }

        if sizeof_type >= 4
            && $arg1.inner() <= u32::MAX.try_into().unwrap()
            && $arg2.inner() <= u32::MAX.try_into().unwrap()
        {
            constants.u32cov.insert((
                $arg1.try_into().expect("failed to convert to cmp args u64"),
                $arg2.try_into().expect("failed to convert to cmp args u64"),
            ));
        }

        if sizeof_type >= 8
            && $arg1.inner() <= u32::MAX.try_into().unwrap()
            && $arg2.inner() <= u32::MAX.try_into().unwrap()
        {
            constants.u64cov.insert((
                $arg1.try_into().expect("failed to convert to cmp args u64"),
                $arg2.try_into().expect("failed to convert to cmp args u64"),
            ));
        }
    };
}

#[no_mangle]
extern "C" fn __sanitizer_cov_trace_cmp8(arg1: u64, arg2: u64) {
    handle_cmp!(CmpOperand::Dynamic(arg1), CmpOperand::Dynamic(arg2), u64);

    let caller_pc = caller_address!();
    TESTCASE_COVERAGE
        .get()
        .expect("failed to get TESTCASE_COVERAGE")
        .lock()
        .expect("failed to lock TESTCASE_COVERAGE")
        .insert(caller_pc);

    //   uintptr_t PC = reinterpret_cast<uintptr_t>(GET_CALLER_PC());
    //   fuzzer::TPC.HandleCmp(PC, Arg1, Arg2);
}

// Now the __sanitizer_cov_trace_const_cmp[1248] callbacks just mimic
// the behaviour of __sanitizer_cov_trace_cmp[1248] ones. This, however,
// should be changed later to make full use of instrumentation.
#[no_mangle]
extern "C" fn __sanitizer_cov_trace_const_cmp8(arg1: u64, arg2: u64) {
    handle_cmp!(CmpOperand::Constant(arg1), CmpOperand::Dynamic(arg2), u64);

    let caller_pc = caller_address!();
    TESTCASE_COVERAGE
        .get()
        .expect("failed to get TESTCASE_COVERAGE")
        .lock()
        .expect("failed to lock TESTCASE_COVERAGE")
        .insert(caller_pc);

    // todo!()
    //   uintptr_t PC = reinterpret_cast<uintptr_t>(GET_CALLER_PC());
    //   fuzzer::TPC.HandleCmp(PC, Arg1, Arg2);
}

#[no_mangle]
extern "C" fn __sanitizer_cov_trace_cmp4(arg1: u32, arg2: u32) {
    handle_cmp!(CmpOperand::Dynamic(arg1), CmpOperand::Dynamic(arg2), u32);

    let caller_pc = caller_address!();
    TESTCASE_COVERAGE
        .get()
        .expect("failed to get TESTCASE_COVERAGE")
        .lock()
        .expect("failed to lock TESTCASE_COVERAGE")
        .insert(caller_pc);

    // todo!()
    //   uintptr_t PC = reinterpret_cast<uintptr_t>(GET_CALLER_PC());
    //   fuzzer::TPC.HandleCmp(PC, Arg1, Arg2);
}

#[no_mangle]
extern "C" fn __sanitizer_cov_trace_const_cmp4(arg1: u32, arg2: u32) {
    handle_cmp!(CmpOperand::Constant(arg1), CmpOperand::Dynamic(arg2), u32);

    let caller_pc = caller_address!();
    TESTCASE_COVERAGE
        .get()
        .expect("failed to get TESTCASE_COVERAGE")
        .lock()
        .expect("failed to lock TESTCASE_COVERAGE")
        .insert(caller_pc);

    //   uintptr_t PC = reinterpret_cast<uintptr_t>(GET_CALLER_PC());
    //   fuzzer::TPC.HandleCmp(PC, Arg1, Arg2);
}

#[no_mangle]
extern "C" fn __sanitizer_cov_trace_cmp2(arg1: u16, arg2: u16) {
    handle_cmp!(CmpOperand::Dynamic(arg1), CmpOperand::Dynamic(arg2), u16);

    let caller_pc = caller_address!();
    TESTCASE_COVERAGE
        .get()
        .expect("failed to get TESTCASE_COVERAGE")
        .lock()
        .expect("failed to lock TESTCASE_COVERAGE")
        .insert(caller_pc);

    //   uintptr_t PC = reinterpret_cast<uintptr_t>(GET_CALLER_PC());
    //   fuzzer::TPC.HandleCmp(PC, Arg1, Arg2);
}

#[no_mangle]
extern "C" fn __sanitizer_cov_trace_const_cmp2(arg1: u16, arg2: u16) {
    handle_cmp!(CmpOperand::Constant(arg1), CmpOperand::Dynamic(arg2), u16);

    let caller_pc = caller_address!();
    TESTCASE_COVERAGE
        .get()
        .expect("failed to get TESTCASE_COVERAGE")
        .lock()
        .expect("failed to lock TESTCASE_COVERAGE")
        .insert(caller_pc);

    //   uintptr_t PC = reinterpret_cast<uintptr_t>(GET_CALLER_PC());
    //   fuzzer::TPC.HandleCmp(PC, Arg1, Arg2);
}

#[no_mangle]
extern "C" fn __sanitizer_cov_trace_cmp1(arg1: u8, arg2: u8) {
    handle_cmp!(CmpOperand::Dynamic(arg1), CmpOperand::Dynamic(arg2), u8);

    let caller_pc = caller_address!();
    TESTCASE_COVERAGE
        .get()
        .expect("failed to get TESTCASE_COVERAGE")
        .lock()
        .expect("failed to lock TESTCASE_COVERAGE")
        .insert(caller_pc);

    //   uintptr_t PC = reinterpret_cast<uintptr_t>(GET_CALLER_PC());
    //   fuzzer::TPC.HandleCmp(PC, Arg1, Arg2);
}

#[no_mangle]
extern "C" fn __sanitizer_cov_trace_const_cmp1(arg1: u8, arg2: u8) {
    handle_cmp!(CmpOperand::Constant(arg1), CmpOperand::Dynamic(arg2), u8);

    let caller_pc = caller_address!();
    TESTCASE_COVERAGE
        .get()
        .expect("failed to get TESTCASE_COVERAGE")
        .lock()
        .expect("failed to lock TESTCASE_COVERAGE")
        .insert(caller_pc);

    //   uintptr_t PC = reinterpret_cast<uintptr_t>(GET_CALLER_PC());
    //   fuzzer::TPC.HandleCmp(PC, Arg1, Arg2);
}

#[no_mangle]
extern "C" fn __sanitizer_cov_trace_switch(_val: u64, _cases: *const u64) {
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
extern "C" fn __sanitizer_cov_trace_div4(_val: u32) {
    let caller_pc = caller_address!();
    TESTCASE_COVERAGE
        .get()
        .expect("failed to get TESTCASE_COVERAGE")
        .lock()
        .expect("failed to lock TESTCASE_COVERAGE")
        .insert(caller_pc);
    //   uintptr_t PC = reinterpret_cast<uintptr_t>(GET_CALLER_PC());
    //   fuzzer::TPC.HandleCmp(PC, Val, (uint32_t)0);
}

#[no_mangle]
extern "C" fn __sanitizer_cov_trace_div8(_val: u64) {
    let caller_pc = caller_address!();
    TESTCASE_COVERAGE
        .get()
        .expect("failed to get TESTCASE_COVERAGE")
        .lock()
        .expect("failed to lock TESTCASE_COVERAGE")
        .insert(caller_pc);
    //   uintptr_t PC = reinterpret_cast<uintptr_t>(GET_CALLER_PC());
    //   fuzzer::TPC.HandleCmp(PC, Val, (uint64_t)0);
}

#[no_mangle]
extern "C" fn __sanitizer_cov_trace_gep(_idx: *const std::ffi::c_void) {
    let caller_pc = caller_address!();
    TESTCASE_COVERAGE
        .get()
        .expect("failed to get TESTCASE_COVERAGE")
        .lock()
        .expect("failed to lock TESTCASE_COVERAGE")
        .insert(caller_pc);

    //   uintptr_t PC = reinterpret_cast<uintptr_t>(GET_CALLER_PC());
    //   fuzzer::TPC.HandleCmp(PC, Idx, (uintptr_t)0);
}

#[no_mangle]
extern "C" fn __sanitizer_weak_hook_memcmp(
    caller_pc: *const std::ffi::c_void,
    s1: *const libc::c_char,
    s2: *const libc::c_char,
    n: usize,
    result: std::os::raw::c_int,
) {
    let caller_pc = caller_pc as usize;
    TESTCASE_COVERAGE
        .get()
        .expect("failed to get TESTCASE_COVERAGE")
        .lock()
        .expect("failed to lock TESTCASE_COVERAGE")
        .insert(caller_pc);

    if result == 0 || n <= 1 {
        // these testcases aren't interesting
        return;
    }

    let constants = COMPARISON_OPERANDS
        .get()
        .expect("constants global not initialized");
    let mut constants = constants
        .lock()
        .expect("failed to lock COMPARISON_OPERANDS global");

    let s1 = unsafe { std::slice::from_raw_parts(s1 as *const u8, n) }.to_vec();
    let s2 = unsafe { std::slice::from_raw_parts(s2 as *const u8, n) }.to_vec();

    constants.binary.insert((s1, s2));

    //   if (!fuzzer::RunningUserCallback) return;
    //   if (result == 0) return;  // No reason to mutate.
    //   if (n <= 1) return;  // Not interesting.
    //   fuzzer::TPC.AddValueForMemcmp(caller_pc, s1, s2, n, /*StopAtZero*/false);
}

#[no_mangle]
extern "C" fn __sanitizer_weak_hook_strncmp(
    caller_pc: *const std::ffi::c_void,
    _s1: *const std::ffi::c_void,
    _s2: *const std::ffi::c_void,
    _n: usize,
    _result: std::os::raw::c_int,
) {
    let caller_pc = caller_pc as usize;
    TESTCASE_COVERAGE
        .get()
        .expect("failed to get TESTCASE_COVERAGE")
        .lock()
        .expect("failed to lock TESTCASE_COVERAGE")
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
    s1: *const libc::c_char,
    s2: *const libc::c_char,
    result: std::os::raw::c_int,
) {
    __sanitizer_weak_hook_memcmp(caller_pc, s1, s2, strlen2(s1, s2), result)
    //   if (!fuzzer::RunningUserCallback) return;
    //   if (result == 0) return;  // No reason to mutate.
    //   size_t N = fuzzer::InternalStrnlen2(s1, s2);
    //   if (N <= 1) return;  // Not interesting.
    //   fuzzer::TPC.AddValueForMemcmp(caller_pc, s1, s2, N, /*StopAtZero*/true);
}

#[no_mangle]
extern "C" fn __sanitizer_weak_hook_strncasecmp(
    caller_pc: *const std::ffi::c_void,
    _s1: *const std::ffi::c_void,
    _s2: *const std::ffi::c_void,
    _n: usize,
    _result: std::os::raw::c_int,
) {
    let caller_pc = caller_pc as usize;
    TESTCASE_COVERAGE
        .get()
        .expect("failed to get TESTCASE_COVERAGE")
        .lock()
        .expect("failed to lock TESTCASE_COVERAGE")
        .insert(caller_pc);

    //   if (!fuzzer::RunningUserCallback) return;
    //   return __sanitizer_weak_hook_strncmp(called_pc, s1, s2, n, result);
}

#[no_mangle]
extern "C" fn __sanitizer_weak_hook_strcasecmp(
    _caller_pc: *const std::ffi::c_void,
    _s1: *const std::ffi::c_void,
    _s2: *const std::ffi::c_void,
    _result: std::os::raw::c_int,
) {
    let caller_pc = caller_address!();
    TESTCASE_COVERAGE
        .get()
        .expect("failed to get TESTCASE_COVERAGE")
        .lock()
        .expect("failed to lock TESTCASE_COVERAGE")
        .insert(caller_pc);
    //   if (!fuzzer::RunningUserCallback) return;
    //   return __sanitizer_weak_hook_strcmp(called_pc, s1, s2, result);
}

#[no_mangle]
extern "C" fn __sanitizer_weak_hook_strstr(
    caller_pc: *const std::ffi::c_void,
    _s1: *const std::ffi::c_void,
    _s2: *const std::ffi::c_void,
    _result: std::os::raw::c_int,
) {
    let caller_pc = caller_pc as usize;
    TESTCASE_COVERAGE
        .get()
        .expect("failed to get TESTCASE_COVERAGE")
        .lock()
        .expect("failed to lock TESTCASE_COVERAGE")
        .insert(caller_pc);
    //   if (!fuzzer::RunningUserCallback) return;
    //   fuzzer::TPC.MMT.Add(reinterpret_cast<const uint8_t *>(s2), strlen(s2));
}

#[no_mangle]
extern "C" fn __sanitizer_weak_hook_strcasestr(
    caller_pc: *const std::ffi::c_void,
    _s1: *const std::ffi::c_void,
    _s2: *const std::ffi::c_void,
    _result: std::os::raw::c_int,
) {
    let caller_pc = caller_pc as usize;
    TESTCASE_COVERAGE
        .get()
        .expect("failed to get TESTCASE_COVERAGE")
        .lock()
        .expect("failed to lock TESTCASE_COVERAGE")
        .insert(caller_pc);
    //   if (!fuzzer::RunningUserCallback) return;
    //   fuzzer::TPC.MMT.Add(reinterpret_cast<const uint8_t *>(s2), strlen(s2));
}

#[no_mangle]
extern "C" fn __sanitizer_weak_hook_memmem(
    caller_pc: *const std::ffi::c_void,
    _s1: *const std::ffi::c_void,
    _len1: usize,
    _s2: *const std::ffi::c_void,
    _len2: usize,
    _result: std::os::raw::c_int,
) {
    let caller_pc = caller_pc as usize;
    TESTCASE_COVERAGE
        .get()
        .expect("failed to get TESTCASE_COVERAGE")
        .lock()
        .expect("failed to lock TESTCASE_COVERAGE")
        .insert(caller_pc);
    //   if (!fuzzer::RunningUserCallback) return;
    //   fuzzer::TPC.MMT.Add(reinterpret_cast<const uint8_t *>(s2), len2);
}

/// Returns the minimum string length of the two arguments
fn strlen2(s1: *const libc::c_char, s2: *const libc::c_char) -> usize {
    let mut len = 0;
    while unsafe { *s1.offset(len) != 0 } && unsafe { *s2.offset(len) != 0 } {
        len += 1;
    }

    return len.try_into().expect("failed to convert len to usze");
}
