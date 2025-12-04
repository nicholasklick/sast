
package main

import (
	"fmt"
	"unsafe"
)

func vulnerable() {
	var x struct {
		a bool
		b int16
		c []int
	}
	// Use of unsafe pointer
	b := (*int16)(unsafe.Pointer(uintptr(unsafe.Pointer(&x)) + unsafe.Offsetof(x.b)))
	*b = 42
	fmt.Println(x)
}
