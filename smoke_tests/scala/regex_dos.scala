// Regular Expression Denial of Service (ReDoS) vulnerabilities in Scala
package com.example.security

import scala.util.matching.Regex

class RegexDosVulnerabilities {

  // Test 1: Catastrophic backtracking
  def validateEmail(email: String): Boolean = {
    // VULNERABLE: Nested quantifiers cause exponential backtracking
    val pattern = "^([a-zA-Z0-9]+)+@[a-zA-Z0-9]+\\.[a-zA-Z]+$".r
    pattern.matches(email)
  }

  // Test 2: Overlapping alternation
  def validateInput(input: String): Boolean = {
    // VULNERABLE: Overlapping patterns
    val pattern = "^(a+|a+b)+$".r
    pattern.matches(input)
  }

  // Test 3: User-provided regex
  def matchPattern(input: String, pattern: String): Boolean = {
    // VULNERABLE: User controls regex
    pattern.r.matches(input)
  }

  // Test 4: Complex URL validation
  def validateUrl(url: String): Boolean = {
    // VULNERABLE: Complex regex with backtracking
    val pattern = "^(https?://)?([\\da-z\\.-]+)\\.([a-z\\.]{2,6})([/\\w \\.-]*)*/?$".r
    pattern.matches(url)
  }

  // Test 5: HTML tag stripping
  def stripHtml(html: String): String = {
    // VULNERABLE: Greedy quantifiers
    val pattern = "<[^>]*>".r
    pattern.replaceAllIn(html, "")
  }

  // Test 6: Password strength regex
  def isStrongPassword(password: String): Boolean = {
    // VULNERABLE: Multiple lookaheads with quantifiers
    val pattern = "^(?=.*[a-z]+)(?=.*[A-Z]+)(?=.*[0-9]+)(?=.*[!@#$%^&*]+).{8,}$".r
    pattern.matches(password)
  }

  // Test 7: Log parsing regex
  def parseLogLine(line: String): Option[List[String]] = {
    // VULNERABLE: Greedy .* patterns
    val pattern = "^(.*) - (.*) \\[(.*?)\\] \"(.*)\" (\\d+) (.*)$".r
    line match {
      case pattern(groups @ _*) => Some(groups.toList)
      case _ => None
    }
  }

  // Test 8: Repeated groups
  def validateFormat(input: String): Boolean = {
    // VULNERABLE: Repeated capturing groups
    val pattern = "^(([a-z])+\\.)+[a-z]+$".r
    pattern.matches(input)
  }

  // Test 9: Whitespace normalization
  def normalizeWhitespace(text: String): String = {
    // VULNERABLE: Multiple spaces on large input
    "\\s+".r.replaceAllIn(text, " ")
  }

  // Test 10: Phone number validation
  def validatePhone(phone: String): Boolean = {
    // VULNERABLE: Alternation with backtracking
    val pattern = "^(\\+\\d{1,3}[- ]?)?(\\(\\d{1,4}\\)[- ]?)?\\d{1,4}([- ]?\\d{1,4}){1,3}$".r
    pattern.matches(phone)
  }

  // Test 11: JSON-like validation
  def validateJsonLike(input: String): Boolean = {
    // VULNERABLE: Recursive-like patterns
    val pattern = "^\\{(\"[^\"]+\":\\s*(\"[^\"]*\"|\\d+|true|false|null),?\\s*)+\\}$".r
    pattern.matches(input)
  }

  // Test 12: Pattern compile from user
  def compileUserPattern(userPattern: String): Regex = {
    // VULNERABLE: User-controlled pattern
    userPattern.r
  }

  // Test 13: Scala regex interpolation
  def dynamicRegex(part: String): Regex = {
    // VULNERABLE: User input in regex interpolation
    s"^$part+$$".r
  }
}
