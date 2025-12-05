// Regular Expression Denial of Service (ReDoS) vulnerabilities in Dart

// Test 1: Evil regex with nested quantifiers
bool vulnerableNestedQuantifiers(String input) {
  // VULNERABLE: Nested quantifiers - exponential backtracking
  var regex = RegExp(r'^(a+)+$');
  return regex.hasMatch(input);
}

// Test 2: Overlapping alternatives
bool vulnerableOverlapping(String input) {
  // VULNERABLE: Overlapping patterns
  var regex = RegExp(r'^(a|a)+$');
  return regex.hasMatch(input);
}

// Test 3: Greedy with backtracking
bool vulnerableGreedy(String input) {
  // VULNERABLE: Greedy pattern with backtracking
  var regex = RegExp(r'^.*.*.*$');
  return regex.hasMatch(input);
}

// Test 4: User-controlled regex
bool vulnerableUserRegex(String pattern, String input) {
  // VULNERABLE: User-controlled regex pattern
  var regex = RegExp(pattern);
  return regex.hasMatch(input);
}

// Test 5: Email regex (common vulnerable pattern)
bool vulnerableEmailRegex(String email) {
  // VULNERABLE: Complex email regex with backtracking
  var regex = RegExp(r'^([a-zA-Z0-9]+([._-][a-zA-Z0-9]+)*)+@([a-zA-Z0-9]+([.-][a-zA-Z0-9]+)*)+$');
  return regex.hasMatch(email);
}

// Test 6: URL regex
bool vulnerableUrlRegex(String url) {
  // VULNERABLE: URL regex with potential backtracking
  var regex = RegExp(r'^(https?://)?([a-zA-Z0-9-]+\.)+[a-zA-Z]+(/[a-zA-Z0-9-._~:/?#\[\]@!$&\'()*+,;=%]*)*$');
  return regex.hasMatch(url);
}

// Test 7: HTML tag matching
String vulnerableHtmlStrip(String html) {
  // VULNERABLE: HTML regex with backtracking
  var regex = RegExp(r'<[^>]*>*');
  return html.replaceAll(regex, '');
}

// Test 8: Repeated group with alternatives
bool vulnerableRepeatedGroup(String input) {
  // VULNERABLE: Repeated group with alternatives
  var regex = RegExp(r'^([a-z]|[A-Z]|[0-9])+$');
  return regex.hasMatch(input);
}

// Test 9: Nested capturing groups
List<String?> vulnerableNestedCapture(String input) {
  // VULNERABLE: Nested capturing groups
  var regex = RegExp(r'^((a+)(b+))+$');
  var match = regex.firstMatch(input);
  return match?.groups([1, 2, 3]) ?? [];
}

// Test 10: Catastrophic backtracking
bool vulnerableCatastrophic(String input) {
  // VULNERABLE: Classic catastrophic backtracking
  var regex = RegExp(r'^(a+)+b$');
  return regex.hasMatch(input);
}

// Test 11: Optional with repetition
bool vulnerableOptionalRepeat(String input) {
  // VULNERABLE: Optional group with repetition
  var regex = RegExp(r'^(a?a?)+$');
  return regex.hasMatch(input);
}

// Test 12: Alternation with overlap
bool vulnerableAlternation(String input) {
  // VULNERABLE: Alternation with overlapping patterns
  var regex = RegExp(r'^(ab|a)+$');
  return regex.hasMatch(input);
}

// Test 13: Complex pattern from config
bool vulnerableConfigPattern(String configPattern, String input) {
  // VULNERABLE: Pattern from configuration
  try {
    var regex = RegExp(configPattern);
    return regex.hasMatch(input);
  } catch (e) {
    return false;
  }
}

// Test 14: Search with user pattern
List<String> vulnerableSearch(String pattern, List<String> items) {
  // VULNERABLE: User pattern in search
  var regex = RegExp(pattern);
  return items.where((item) => regex.hasMatch(item)).toList();
}

// Test 15: Split with user regex
List<String> vulnerableSplit(String input, String pattern) {
  // VULNERABLE: User pattern in split
  return input.split(RegExp(pattern));
}

// Test 16: Replace with user regex
String vulnerableReplace(String input, String pattern, String replacement) {
  // VULNERABLE: User pattern in replace
  return input.replaceAll(RegExp(pattern), replacement);
}

// Test 17: Quadratic blowup
bool vulnerableQuadratic(String input) {
  // VULNERABLE: Quadratic complexity
  var regex = RegExp(r'^(.*?,)+.*$');
  return regex.hasMatch(input);
}

// Test 18: Match all with vulnerable pattern
Iterable<RegExpMatch> vulnerableMatchAll(String input) {
  // VULNERABLE: Match all with backtracking pattern
  var regex = RegExp(r'(a+)+');
  return regex.allMatches(input);
}
