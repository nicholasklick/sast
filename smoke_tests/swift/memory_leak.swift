// Memory Leak and Unsafe Memory vulnerabilities in Swift
import Foundation

class MemoryLeakVulnerabilities {

    // Test 1: Strong reference cycle
    class Node {
        var value: Int
        var next: Node?  // VULNERABLE: Should be weak

        init(value: Int) {
            self.value = value
        }
    }

    func createCycle() {
        let node1 = Node(value: 1)
        let node2 = Node(value: 2)
        // VULNERABLE: Circular reference
        node1.next = node2
        node2.next = node1
    }

    // Test 2: Closure capture cycle
    class DataLoader {
        var data: Data?
        var completion: (() -> Void)?

        func load() {
            // VULNERABLE: self captured strongly
            completion = {
                self.data = Data()
            }
        }
    }

    // Test 3: Delegate retain cycle
    class ViewController {
        var delegate: ViewControllerDelegate?
    }

    protocol ViewControllerDelegate: AnyObject {}

    class Manager: ViewControllerDelegate {
        var viewController: ViewController

        init() {
            viewController = ViewController()
            // VULNERABLE: Delegate should be weak
            viewController.delegate = self
        }
    }

    // Test 4: Timer retain cycle
    class TimerHolder {
        var timer: Timer?

        func startTimer() {
            // VULNERABLE: Timer retains target
            timer = Timer.scheduledTimer(timeInterval: 1.0,
                                        target: self,
                                        selector: #selector(tick),
                                        userInfo: nil,
                                        repeats: true)
        }

        @objc func tick() {}
    }

    // Test 5: NotificationCenter retain
    class Observer {
        init() {
            // VULNERABLE: Observer never removed
            NotificationCenter.default.addObserver(
                self,
                selector: #selector(handleNotification),
                name: .init("test"),
                object: nil
            )
        }

        @objc func handleNotification() {}
    }

    // Test 6: Unsafe pointer usage
    func unsafePointerAccess() {
        let pointer = UnsafeMutablePointer<Int>.allocate(capacity: 10)
        pointer.initialize(repeating: 0, count: 10)
        // VULNERABLE: Never deallocated
        // pointer.deallocate() is missing
    }

    // Test 7: Unbalanced retain
    func unbalancedRetain(object: AnyObject) {
        // VULNERABLE: Manual retain without release
        _ = Unmanaged.passRetained(object)
    }

    // Test 8: DispatchSource leak
    func createDispatchSource() -> DispatchSourceTimer {
        let source = DispatchSource.makeTimerSource()
        // VULNERABLE: Source captured but never cancelled
        source.setEventHandler { [unowned self] in
            self.handleEvent()
        }
        source.resume()
        return source
    }

    func handleEvent() {}

    // Test 9: URLSession delegate cycle
    class NetworkManager: NSObject, URLSessionDelegate {
        lazy var session: URLSession = {
            // VULNERABLE: Delegate retained
            return URLSession(configuration: .default, delegate: self, delegateQueue: nil)
        }()
    }

    // Test 10: CADisplayLink retain
    class AnimationController {
        var displayLink: CADisplayLink?

        func startAnimation() {
            // VULNERABLE: CADisplayLink retains target
            displayLink = CADisplayLink(target: self, selector: #selector(update))
            displayLink?.add(to: .main, forMode: .common)
        }

        @objc func update() {}
    }

    // Test 11: Recursive closure
    func recursiveClosure() {
        var closure: (() -> Void)?
        // VULNERABLE: Closure retains itself
        closure = {
            closure?()
        }
    }

    // Test 12: Autoreleasepool missing
    func processLargeData() {
        for _ in 0..<10000 {
            // VULNERABLE: Should use autoreleasepool
            let _ = Data(count: 1024 * 1024)
        }
    }
}

class CADisplayLink {
    init(target: Any, selector: Selector) {}
    func add(to: RunLoop, forMode: RunLoop.Mode) {}
}
