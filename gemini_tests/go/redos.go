
package main

import (
	"fmt"
	"regexp"
)

func main() {
	// A complex regex can be vulnerable to ReDoS
	re, _ := regexp.Compile("^(a+)+$")
	match := re.MatchString("aaaaaaaaaaaaaaaaaaaaaaaaaaaaab")
	fmt.Println(match)
}
