// Dynamic Code Execution vulnerabilities in Groovy
package com.example.security

class DynamicCodeVulnerabilities {

    // Test 1: Eval.me with user input
    def evalUserCode(String code) {
        // VULNERABLE: Direct code evaluation
        Eval.me(code)
    }

    // Test 2: Eval.x with variable binding
    def evalWithBinding(String code, Object x) {
        // VULNERABLE: User code with binding
        Eval.x(x, code)
    }

    // Test 3: Eval.xy with multiple bindings
    def evalWithMultipleBindings(String code, Object x, Object y) {
        // VULNERABLE: User code with multiple bindings
        Eval.xy(x, y, code)
    }

    // Test 4: GroovyShell evaluate
    def shellEvaluate(String script) {
        // VULNERABLE: Shell script execution
        def shell = new GroovyShell()
        shell.evaluate(script)
    }

    // Test 5: GroovyShell with binding
    def shellWithBinding(String script, Map variables) {
        // VULNERABLE: Shell with user binding
        def binding = new Binding(variables)
        def shell = new GroovyShell(binding)
        shell.evaluate(script)
    }

    // Test 6: GroovyShell parse and run
    def parseAndRun(String script) {
        // VULNERABLE: Parse and execute script
        def shell = new GroovyShell()
        def parsed = shell.parse(script)
        parsed.run()
    }

    // Test 7: GroovyClassLoader
    def loadUserClass(String classCode) {
        // VULNERABLE: Loading user-defined class
        def loader = new GroovyClassLoader()
        def clazz = loader.parseClass(classCode)
        clazz.getDeclaredConstructor().newInstance()
    }

    // Test 8: Script from file path
    def runScriptFile(String filePath) {
        // VULNERABLE: User-controlled file path
        def shell = new GroovyShell()
        shell.evaluate(new File(filePath))
    }

    // Test 9: GString execution
    String executeGString(String template, Map data) {
        // VULNERABLE: GString with user template
        def shell = new GroovyShell(new Binding(data))
        shell.evaluate("\"${template}\"")
    }

    // Test 10: MethodClosure invocation
    def invokeMethodClosure(Object target, String methodName) {
        // VULNERABLE: Method name from user
        def closure = target.&"${methodName}"
        closure.call()
    }

    // Test 11: Dynamic method missing
    def methodMissing(String name, args) {
        // VULNERABLE: Dynamic method execution
        def shell = new GroovyShell()
        shell.evaluate("${name}(${args.join(',')})")
    }

    // Test 12: ConfigSlurper code execution
    def parseConfig(String configScript) {
        // VULNERABLE: Config with embedded code
        def slurper = new ConfigSlurper()
        slurper.parse(configScript)
    }

    // Test 13: Script engine manager
    def useScriptEngine(String code) {
        // VULNERABLE: Script engine execution
        def engine = new javax.script.ScriptEngineManager().getEngineByName("groovy")
        engine.eval(code)
    }

    // Test 14: Builder evaluate
    def buildWithEval(String builderCode) {
        // VULNERABLE: Builder code from user
        def writer = new StringWriter()
        def builder = new groovy.xml.MarkupBuilder(writer)
        Eval.x(builder, "x.${builderCode}")
        writer.toString()
    }
}
