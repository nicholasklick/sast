// Integer Overflow Test Cases

// Test 1: Array size calculation overflow
fn allocate_buffer(element_count: usize, element_size: usize) -> Vec<u8> {
    // VULNERABLE: element_count * element_size could overflow
    let total_size = element_count * element_size;
    vec![0u8; total_size]
}

// Test 2: Addition overflow in financial calculation
fn calculate_total_price(price: u64, quantity: u64, tax_rate: u64) -> u64 {
    // VULNERABLE: Calculations could overflow
    let subtotal = price * quantity;
    let tax = subtotal * tax_rate / 100;
    subtotal + tax
}

// Test 3: Bitwise operations leading to overflow
fn compute_hash(value: u32) -> u32 {
    // VULNERABLE: Bit shifting can cause unexpected results
    (value << 16) | (value >> 16)
}

// Test 4: Array index calculation
fn get_element_at<T>(array: &[T], base_index: usize, offset: isize) -> Option<&T> {
    // VULNERABLE: base_index + offset could overflow or become invalid
    let index = (base_index as isize + offset) as usize;
    array.get(index)
}

// Test 5: Time calculation overflow
fn add_milliseconds(timestamp: u64, milliseconds: u64) -> u64 {
    // VULNERABLE: Adding to timestamp could overflow
    timestamp + milliseconds
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_overflow_scenarios() {
        // These could overflow in release mode
        let _ = allocate_buffer(1000000, 1000000);
        let _ = calculate_total_price(u64::MAX / 2, 3, 10);
    }
}
