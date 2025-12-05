// Integer Overflow/Underflow vulnerabilities in Swift
import Foundation

class IntegerOverflowVulnerabilities {

    // Test 1: Unchecked addition
    func addValues(a: Int, b: Int) -> Int {
        // VULNERABLE: Can overflow
        return a + b
    }

    // Test 2: Unchecked multiplication
    func multiplyValues(a: Int, b: Int) -> Int {
        // VULNERABLE: Can overflow
        return a * b
    }

    // Test 3: Array size calculation
    func allocateBuffer(count: Int, elementSize: Int) -> Data {
        // VULNERABLE: count * elementSize can overflow
        let totalSize = count * elementSize
        return Data(count: totalSize)
    }

    // Test 4: Price calculation
    func calculateTotal(quantity: Int, price: Int) -> Int {
        // VULNERABLE: Can overflow with large values
        return quantity * price
    }

    // Test 5: Unchecked subtraction (underflow)
    func subtractValues(a: UInt, b: UInt) -> UInt {
        // VULNERABLE: Can underflow if b > a
        return a - b
    }

    // Test 6: Type conversion overflow
    func convertToInt32(value: Int64) -> Int32 {
        // VULNERABLE: Truncation if value > Int32.max
        return Int32(value)
    }

    // Test 7: Loop counter overflow
    func processItems(count: Int) {
        var processed = 0
        // VULNERABLE: processed can overflow
        for _ in 0..<count {
            processed += 1
        }
    }

    // Test 8: Balance update
    func updateBalance(current: Int, amount: Int) -> Int {
        // VULNERABLE: Overflow can make balance negative-like
        return current + amount
    }

    // Test 9: Time calculation overflow
    func calculateFutureTime(current: UInt64, offsetDays: UInt64) -> UInt64 {
        let secondsPerDay: UInt64 = 86400
        // VULNERABLE: Large offsetDays can overflow
        return current + (offsetDays * secondsPerDay)
    }

    // Test 10: String repeat overflow
    func repeatString(str: String, count: Int) -> String {
        // VULNERABLE: Large count can cause memory issues
        return String(repeating: str, count: count)
    }

    // Test 11: Unchecked increment
    func incrementCounter(counter: inout Int) {
        // VULNERABLE: No overflow check
        counter += 1
    }

    // Test 12: Division by negative result
    func divideWithCheck(a: Int, b: Int) -> Int? {
        // VULNERABLE: Int.min / -1 overflows
        if b == 0 { return nil }
        return a / b
    }

    // Test 13: Shift overflow
    func shiftLeft(value: Int, positions: Int) -> Int {
        // VULNERABLE: Shifting can overflow
        return value << positions
    }

    // Test 14: User input size
    func processUserInput(sizeHeader: String) -> Data? {
        guard let size = Int(sizeHeader) else { return nil }
        // VULNERABLE: Malicious size value
        return Data(count: size)
    }

    // Test 15: Percentage calculation
    func calculatePercentage(value: Int, percentage: Int) -> Int {
        // VULNERABLE: Intermediate overflow
        return (value * percentage) / 100
    }

    // Safe alternatives using overflow operators
    func safeAdd(a: Int, b: Int) -> Int? {
        let (result, overflow) = a.addingReportingOverflow(b)
        return overflow ? nil : result
    }

    func safeMultiply(a: Int, b: Int) -> Int? {
        let (result, overflow) = a.multipliedReportingOverflow(by: b)
        return overflow ? nil : result
    }
}
