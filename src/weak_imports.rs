use crate::weak::weak;

pub(crate) fn libfuzzer_runone_fn() -> unsafe extern "C" fn(*const u8, usize) -> std::os::raw::c_int
{
    #[allow(non_snake_case)]
    {
        weak!(fn LLVMFuzzerTestOneInput(*const u8, usize) -> std::os::raw::c_int);

        LLVMFuzzerTestOneInput
            .get()
            .expect("failed to get LLVMFuzzerTestOneInput")
    }
}

pub(crate) fn libfuzzer_initialize_fn() -> Option<
    unsafe extern "C" fn(
        *mut std::os::raw::c_int,
        *mut *const *const libc::c_char,
    ) -> std::os::raw::c_int,
> {
    #[allow(non_snake_case)]
    {
        weak!(fn LLVMFuzzerInitialize(*mut std::os::raw::c_int, *mut *const *const libc::c_char) -> std::os::raw::c_int);

        LLVMFuzzerInitialize.get()
    }
}

pub(crate) fn sanitizer_set_death_callback_fn(
) -> Option<unsafe extern "C" fn(extern "C" fn()) -> std::ffi::c_void> {
    #[allow(non_snake_case)]
    {
        weak!(fn __sanitizer_set_death_callback(extern "C" fn()) -> std::ffi::c_void);

        __sanitizer_set_death_callback.get()
    }
}

pub(crate) fn asan_unpoison_memory_region_fn(
) -> Option<unsafe extern "C" fn(*const u8, usize) -> std::os::raw::c_void> {
    weak!(fn __asan_unpoison_memory_region(*const u8, usize) -> std::os::raw::c_void);

    __asan_unpoison_memory_region.get()
}

pub(crate) fn asan_poison_memory_region_fn(
) -> Option<unsafe extern "C" fn(*const u8, usize) -> std::os::raw::c_void> {
    weak!(fn __asan_poison_memory_region(*const u8, usize) -> std::os::raw::c_void);

    __asan_poison_memory_region.get()
}

pub(crate) fn msan_unpoison_memory_region_fn(
) -> Option<unsafe extern "C" fn(*const u8, usize) -> std::os::raw::c_void> {
    weak!(fn __msan_unpoison_memory_region(*const u8, usize) -> std::os::raw::c_void);

    __msan_unpoison_memory_region.get()
}

pub(crate) fn msan_poison_memory_region_fn(
) -> Option<unsafe extern "C" fn(*const u8, usize) -> std::os::raw::c_void> {
    weak!(fn __msan_poison_memory_region(*const u8, usize) -> std::os::raw::c_void);

    __msan_poison_memory_region.get()
}
