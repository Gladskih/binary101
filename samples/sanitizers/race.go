package main

import "sync"

func main() {
	var workers sync.WaitGroup
	workers.Add(1)
	go func() { defer workers.Done() }()
	workers.Wait()
}
