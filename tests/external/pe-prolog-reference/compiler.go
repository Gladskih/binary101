package main

import "runtime"

//go:noinline
func leaf(value int) int { return value*3 + 1 }

//go:noinline
func frame(seed int) int {
	var values [1024]int
	for index := range values {
		values[index] = seed + index
	}
	runtime.KeepAlive(&values)
	return values[seed&1023] ^ leaf(seed)
}

func main() {
	if frame(17) == 0 {
		panic("control")
	}
}
