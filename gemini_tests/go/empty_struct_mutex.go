
package main

import (
	"fmt"
	"sync"
)

type Resource struct {
	// Empty struct in a mutex can lead to deadlocks if not used carefully
}

var (
	lock = sync.Mutex{}
	r    = Resource{}
)

func main() {
	lock.Lock()
	// do stuff with r
	lock.Unlock()
	fmt.Println("done")
}
