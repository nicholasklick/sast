// Integer Overflow Test Cases

// Test 1: Array size calculation overflow
function allocateBuffer(elementCount: number, elementSize: number): Buffer {
    // VULNERABLE: elementCount * elementSize could overflow
    const totalSize = elementCount * elementSize;
    return Buffer.alloc(totalSize);
}

// Test 2: Addition overflow in financial calculation
function calculateTotalPrice(price: number, quantity: number, taxRate: number): number {
    // VULNERABLE: Calculations could overflow Number.MAX_SAFE_INTEGER
    const subtotal = price * quantity;
    const tax = subtotal * taxRate;
    return subtotal + tax;
}

// Test 3: Bitwise operations leading to overflow
function computeHash(value: number): number {
    // VULNERABLE: Bit shifting can cause unexpected results
    return (value << 16) | (value >> 16);
}

// Test 4: Array index calculation
function getElementAt(array: any[], baseIndex: number, offset: number): any {
    // VULNERABLE: baseIndex + offset could overflow or become negative
    const index = baseIndex + offset;
    return array[index];
}

// Test 5: Time calculation overflow
function addMilliseconds(timestamp: number, milliseconds: number): number {
    // VULNERABLE: Adding to timestamp could exceed MAX_SAFE_INTEGER
    return timestamp + milliseconds;
}
