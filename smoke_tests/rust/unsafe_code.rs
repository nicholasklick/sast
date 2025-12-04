// Unsafe Rust code vulnerabilities

fn buffer_overflow_risk(data: &[u8], index: usize) -> u8 {
    // VULNERABLE: Unchecked array access
    unsafe {
        *data.get_unchecked(index)
    }
}

fn raw_pointer_deref(ptr: *const i32) -> i32 {
    // VULNERABLE: Dereferencing raw pointer without validation
    unsafe {
        *ptr
    }
}

fn use_after_free_risk() -> *mut String {
    // VULNERABLE: Returning pointer to local data
    let s = String::from("hello");
    let ptr = &s as *const String as *mut String;
    ptr
}

fn transmute_danger<T, U>(value: T) -> U {
    // VULNERABLE: Unsafe transmute without size check
    unsafe {
        std::mem::transmute_copy(&value)
    }
}

fn mutable_static_access() {
    // VULNERABLE: Mutable static without synchronization
    static mut COUNTER: i32 = 0;
    unsafe {
        COUNTER += 1;
    }
}
