// Closure Injection vulnerabilities in Groovy
package com.example.security

class ClosureInjectionVulnerabilities {

    // Test 1: Eval with user closure code
    def executeUserClosure(String closureCode) {
        // VULNERABLE: User-defined closure code
        def closure = Eval.me("{ -> ${closureCode} }")
        closure.call()
    }

    // Test 2: GroovyShell closure parsing
    def parseUserClosure(String code) {
        // VULNERABLE: Closure from user input
        def shell = new GroovyShell()
        def closure = shell.evaluate("{ it -> ${code} }")
        closure
    }

    // Test 3: Dynamic delegate assignment
    def runWithDelegate(Closure closure, Object delegate) {
        // VULNERABLE: Arbitrary delegate
        closure.delegate = delegate
        closure.resolveStrategy = Closure.DELEGATE_FIRST
        closure.call()
    }

    // Test 4: Closure coercion attack
    def coerceToInterface(String code) {
        // VULNERABLE: Closure as interface
        def shell = new GroovyShell()
        def closure = shell.evaluate(code)
        closure as Runnable
    }

    // Test 5: Metaclass closure injection
    void addMethodDynamically(Class clazz, String methodName, String closureCode) {
        // VULNERABLE: Adding methods from user code
        def shell = new GroovyShell()
        def closure = shell.evaluate("{ -> ${closureCode} }")
        clazz.metaClass."${methodName}" = closure
    }

    // Test 6: with closure injection
    def executeWith(Object target, String code) {
        // VULNERABLE: User code in with block
        def shell = new GroovyShell()
        target.with(shell.evaluate("{ -> ${code} }"))
    }

    // Test 7: Collect with user transform
    List transformList(List items, String transformCode) {
        // VULNERABLE: User transform function
        def shell = new GroovyShell()
        def transform = shell.evaluate("{ it -> ${transformCode} }")
        items.collect(transform)
    }

    // Test 8: FindAll with user predicate
    List filterList(List items, String predicateCode) {
        // VULNERABLE: User filter predicate
        def shell = new GroovyShell()
        def predicate = shell.evaluate("{ it -> ${predicateCode} }")
        items.findAll(predicate)
    }

    // Test 9: Sort with user comparator
    List sortList(List items, String comparatorCode) {
        // VULNERABLE: User sort comparator
        def shell = new GroovyShell()
        def comparator = shell.evaluate("{ a, b -> ${comparatorCode} }")
        items.sort(comparator)
    }

    // Test 10: Each with user action
    void processEach(List items, String actionCode) {
        // VULNERABLE: User action closure
        def shell = new GroovyShell()
        def action = shell.evaluate("{ it -> ${actionCode} }")
        items.each(action)
    }

    // Test 11: Inject/fold with user reducer
    def reduceList(List items, Object initial, String reducerCode) {
        // VULNERABLE: User reducer function
        def shell = new GroovyShell()
        def reducer = shell.evaluate("{ acc, it -> ${reducerCode} }")
        items.inject(initial, reducer)
    }

    // Test 12: Timer task from closure
    void scheduleTask(String taskCode, long delay) {
        // VULNERABLE: User task code
        def shell = new GroovyShell()
        def task = shell.evaluate("{ -> ${taskCode} }")
        new Timer().runAfter(delay, task)
    }

    // Test 13: Builder closure injection
    def buildWithClosure(String builderCode) {
        // VULNERABLE: User builder closure
        def shell = new GroovyShell()
        def builder = new groovy.xml.MarkupBuilder()
        def closure = shell.evaluate("{ builder -> ${builderCode} }")
        closure.call(builder)
    }
}
