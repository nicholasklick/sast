// Coroutine Safety vulnerabilities in Kotlin
package com.example.security

import kotlinx.coroutines.*
import kotlinx.coroutines.sync.Mutex
import java.util.concurrent.atomic.AtomicInteger

class CoroutineSafetyVulnerabilities {

    // Test 1: Shared mutable state without synchronization
    private var counter = 0

    suspend fun incrementCounter() {
        // VULNERABLE: Race condition in coroutines
        counter++
    }

    // Test 2: GlobalScope misuse
    fun fireAndForget(data: String) {
        // VULNERABLE: No structured concurrency, exceptions lost
        GlobalScope.launch {
            processData(data)
        }
    }

    // Test 3: runBlocking in production code
    fun blockingCall(): String {
        // VULNERABLE: Can cause deadlocks
        return runBlocking {
            fetchData()
        }
    }

    // Test 4: Unhandled exception in launch
    fun launchWithoutHandler(scope: CoroutineScope) {
        // VULNERABLE: Exception crashes parent
        scope.launch {
            throw RuntimeException("Unhandled")
        }
    }

    // Test 5: Shared collection modification
    private val items = mutableListOf<String>()

    suspend fun addItem(item: String) {
        // VULNERABLE: Non-thread-safe collection
        items.add(item)
    }

    // Test 6: Cancelled scope reuse
    private var scope: CoroutineScope? = null

    fun launchTask() {
        // VULNERABLE: Reusing cancelled scope
        scope?.launch {
            doWork()
        }
    }

    // Test 7: Blocking IO in default dispatcher
    suspend fun readFile(path: String): String {
        // VULNERABLE: Should use Dispatchers.IO
        return java.io.File(path).readText()
    }

    // Test 8: withTimeout resource leak
    suspend fun processWithTimeout(data: String) {
        // VULNERABLE: Resource may not be cleaned up
        val resource = acquireResource()
        withTimeout(1000) {
            resource.process(data)
        }
        // resource.release() may never be called
    }

    // Test 9: SupervisorJob misunderstanding
    fun supervisionMisuse(scope: CoroutineScope) {
        // VULNERABLE: SupervisorJob doesn't prevent crashes
        scope.launch(SupervisorJob()) {
            launch {
                throw RuntimeException() // Still crashes this subtree
            }
        }
    }

    // Test 10: Thread confinement violation
    private val mainThreadData = mutableMapOf<String, Any>()

    suspend fun updateFromBackground(key: String, value: Any) {
        withContext(Dispatchers.Default) {
            // VULNERABLE: Accessing main thread data from background
            mainThreadData[key] = value
        }
    }

    // Test 11: Channel leaks
    suspend fun processMessages() {
        val channel = kotlinx.coroutines.channels.Channel<String>()
        // VULNERABLE: Channel never closed
        GlobalScope.launch {
            for (msg in channel) {
                process(msg)
            }
        }
    }

    // Test 12: Flow without proper error handling
    fun unsafeFlow() = kotlinx.coroutines.flow.flow {
        // VULNERABLE: No error handling
        emit(fetchUnsafeData())
    }

    // Test 13: Mutex not released on exception
    private val mutex = Mutex()

    suspend fun criticalSection(action: suspend () -> Unit) {
        mutex.lock()
        // VULNERABLE: If action throws, mutex stays locked
        action()
        mutex.unlock()
    }

    private suspend fun processData(data: String) {}
    private suspend fun fetchData(): String = ""
    private suspend fun doWork() {}
    private fun acquireResource(): Resource = Resource()
    private fun process(msg: String) {}
    private fun fetchUnsafeData(): String = ""
}

class Resource {
    fun process(data: String) {}
    fun release() {}
}
