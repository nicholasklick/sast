// Insecure Deserialization vulnerabilities in Dart

import 'dart:convert';
import 'dart:io';
import 'dart:mirrors';

// Test 1: JSON decode without validation
dynamic vulnerableJsonDecode(String userInput) {
  // VULNERABLE: Deserializing untrusted JSON
  return jsonDecode(userInput);
}

// Test 2: JSON from file without validation
Future<dynamic> vulnerableJsonFile(String filePath) async {
  // VULNERABLE: Loading JSON from untrusted file
  var file = File(filePath);
  var content = await file.readAsString();
  return jsonDecode(content);
}

// Test 3: JSON from HTTP response
Future<dynamic> vulnerableJsonHttp(String url) async {
  // VULNERABLE: Deserializing HTTP response
  var client = HttpClient();
  var request = await client.getUrl(Uri.parse(url));
  var response = await request.close();
  var body = await response.transform(utf8.decoder).join();
  return jsonDecode(body);
}

// Test 4: Creating object from JSON type field
dynamic vulnerableTypeInstantiation(String json) {
  // VULNERABLE: Type from user input
  var data = jsonDecode(json);
  var typeName = data['type'];
  // Simulating dynamic instantiation
  return 'Created: $typeName';
}

// Test 5: Reflection with user input
void vulnerableMirrorInvoke(String className, String methodName, List args) {
  // VULNERABLE: Reflection with user input
  var classMirror = reflectClass(Object);
  var instanceMirror = classMirror.newInstance(Symbol(''), []);
  instanceMirror.invoke(Symbol(methodName), args);
}

// Test 6: Dynamic function lookup (simplified)
void vulnerableFunctionApply(String funcName, List<dynamic> args) {
  // VULNERABLE: Dynamic function call based on user input
  var funcMap = <String, void Function(List)>{};
  var func = funcMap[funcName];
  if (func != null) {
    func(args);
  }
}

// Test 7: YAML-like parsing (simulated)
dynamic vulnerableYamlParse(String yamlContent) {
  // VULNERABLE: Parsing untrusted YAML-like content
  // In real Dart, yaml package could have similar issues
  var lines = yamlContent.split('\n');
  var result = <String, dynamic>{};
  for (var line in lines) {
    var parts = line.split(':');
    if (parts.length == 2) {
      result[parts[0].trim()] = parts[1].trim();
    }
  }
  return result;
}

// Test 8: Deserialize from WebSocket
Future<void> vulnerableWebSocketDeserialize(String wsUrl) async {
  // VULNERABLE: Deserializing WebSocket messages
  var socket = await WebSocket.connect(wsUrl);
  socket.listen((data) {
    var message = jsonDecode(data);
    processMessage(message);
  });
}

void processMessage(dynamic message) {
  print('Processing: $message');
}

// Test 9: Base64 decode and parse
dynamic vulnerableBase64Decode(String encoded) {
  // VULNERABLE: Decoding and parsing base64 data
  var decoded = utf8.decode(base64Decode(encoded));
  return jsonDecode(decoded);
}

// Test 10: Deserialize from SharedPreferences
Future<dynamic> vulnerablePrefsDeserialize(String key) async {
  // VULNERABLE: Deserializing stored data
  // SharedPreferences prefs = await SharedPreferences.getInstance();
  // var stored = prefs.getString(key);
  var stored = '{"key": "value"}'; // Simulated
  return jsonDecode(stored);
}

// Test 11: XML parsing (simulated)
dynamic vulnerableXmlParse(String xmlContent) {
  // VULNERABLE: Parsing untrusted XML
  // In real Dart, xml package usage
  return 'Parsed XML: $xmlContent';
}

// Test 12: MessagePack deserialization (simulated)
dynamic vulnerableMsgPackDecode(List<int> data) {
  // VULNERABLE: MessagePack deserialization
  // Using msgpack package in real code
  return utf8.decode(data);
}

// Test 13: Protocol Buffer parsing (simulated)
dynamic vulnerableProtobufParse(List<int> data) {
  // VULNERABLE: Protobuf parsing without validation
  return 'Protobuf data: ${data.length} bytes';
}

// Test 14: Deserialize from clipboard
Future<dynamic> vulnerableClipboardDeserialize() async {
  // VULNERABLE: Deserializing clipboard content
  // var clipboardData = await Clipboard.getData('text/plain');
  var clipboardData = '{"data": "from clipboard"}'; // Simulated
  return jsonDecode(clipboardData);
}

// Test 15: Dynamic class loading (simulated)
dynamic vulnerableDynamicLoad(String className) {
  // VULNERABLE: Loading class by name
  // This pattern can lead to arbitrary code execution
  return 'Would load class: $className';
}
