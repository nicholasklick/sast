// Unsafe Serialization vulnerabilities in Kotlin (Kotlinx.serialization specific)
package com.example.security

import kotlinx.serialization.*
import kotlinx.serialization.json.*

class UnsafeSerializationVulnerabilities {

    private val json = Json {
        ignoreUnknownKeys = true
        isLenient = true
    }

    // Test 1: Polymorphic deserialization without restrictions
    @Serializable
    sealed class Command {
        @Serializable
        @SerialName("execute")
        data class Execute(val cmd: String) : Command()
    }

    fun deserializeCommand(jsonString: String): Command {
        // VULNERABLE: Polymorphic type from user
        return json.decodeFromString(jsonString)
    }

    // Test 2: Dynamic type parameter
    inline fun <reified T> deserialize(jsonString: String): T {
        // VULNERABLE: Type could be anything
        return json.decodeFromString(jsonString)
    }

    // Test 3: Contextual serialization
    @Serializable
    data class ConfigurableType(
        @Contextual val handler: Any
    )

    fun deserializeContextual(jsonString: String): ConfigurableType {
        // VULNERABLE: Contextual type resolution
        return json.decodeFromString(jsonString)
    }

    // Test 4: Open polymorphism
    @OptIn(ExperimentalSerializationApi::class)
    val openJson = Json {
        classDiscriminator = "type"
        serializersModule = SerializersModule {
            polymorphic(Any::class) {
                // VULNERABLE: Open polymorphism
            }
        }
    }

    // Test 5: Custom serializer with code execution
    @Serializable(with = CustomSerializer::class)
    data class DangerousPayload(val data: String)

    // Test 6: JSON element manipulation
    fun processJsonElement(jsonString: String): Any? {
        val element = json.parseToJsonElement(jsonString)
        // VULNERABLE: Processing arbitrary JSON structure
        return when (element) {
            is JsonObject -> processObject(element)
            is JsonArray -> processArray(element)
            else -> null
        }
    }

    // Test 7: Class instantiation from JSON
    fun instantiateFromJson(jsonString: String, className: String): Any? {
        // VULNERABLE: Class name from JSON
        val clazz = Class.forName(className)
        val data = json.parseToJsonElement(jsonString)
        return deserializeToClass(clazz, data)
    }

    // Test 8: Prototype pollution-like via JSON
    @Serializable
    data class UserSettings(
        val theme: String = "light",
        val __proto__: Map<String, String>? = null // VULNERABLE
    )

    fun updateSettings(jsonString: String): UserSettings {
        return json.decodeFromString(jsonString)
    }

    // Test 9: Large number deserialization
    fun deserializeLargeNumber(jsonString: String): Long {
        // VULNERABLE: Could overflow or cause DoS
        val element = json.parseToJsonElement(jsonString)
        return element.jsonPrimitive.long
    }

    // Test 10: Nested object depth
    fun deserializeDeeplyNested(jsonString: String): JsonElement {
        // VULNERABLE: Stack overflow with deep nesting
        return json.parseToJsonElement(jsonString)
    }

    // Test 11: Duplicate key handling
    fun processWithDuplicates(jsonString: String): Map<String, Any?> {
        // VULNERABLE: Behavior with duplicate keys undefined
        return json.decodeFromString(jsonString)
    }

    // Test 12: Streaming deserialization
    fun streamDeserialize(inputStream: java.io.InputStream): List<Any> {
        // VULNERABLE: Processing unbounded stream
        val reader = inputStream.bufferedReader()
        val results = mutableListOf<Any>()
        reader.forEachLine { line ->
            results.add(json.decodeFromString<JsonElement>(line))
        }
        return results
    }

    private fun processObject(obj: JsonObject): Any? = null
    private fun processArray(arr: JsonArray): Any? = null
    private fun deserializeToClass(clazz: Class<*>, data: JsonElement): Any? = null
}

@OptIn(ExperimentalSerializationApi::class)
@Serializer(forClass = UnsafeSerializationVulnerabilities.DangerousPayload::class)
object CustomSerializer : KSerializer<UnsafeSerializationVulnerabilities.DangerousPayload> {
    override val descriptor: SerialDescriptor = PrimitiveSerialDescriptor("DangerousPayload", PrimitiveKind.STRING)

    override fun deserialize(decoder: Decoder): UnsafeSerializationVulnerabilities.DangerousPayload {
        val data = decoder.decodeString()
        // VULNERABLE: Custom deserialization logic
        return UnsafeSerializationVulnerabilities.DangerousPayload(data)
    }

    override fun serialize(encoder: Encoder, value: UnsafeSerializationVulnerabilities.DangerousPayload) {
        encoder.encodeString(value.data)
    }
}
