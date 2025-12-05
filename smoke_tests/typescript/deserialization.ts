// Insecure Deserialization vulnerabilities in TypeScript
import { serialize, deserialize } from 'some-serializer';

class DeserializationVulnerabilities {
    // VULNERABLE: Deserializing untrusted data
    deserializeUserData(data: string): any {
        return JSON.parse(data);  // Can be safe, but often misused
    }

    // VULNERABLE: eval-based deserialization
    unsafeDeserialize(serialized: string): any {
        return eval('(' + serialized + ')');
    }

    // VULNERABLE: Function constructor
    dynamicFunction(code: string): Function {
        return new Function(code);
    }

    // VULNERABLE: Using node-serialize (known vulnerable)
    nodeSerializeVuln(data: string): any {
        return deserialize(data);
    }
}
