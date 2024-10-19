package main

import "fmt"

func main() {
	opts := DefaultOptions()
	sniffer, err := NewSniffer(opts)
	if err != nil {
		exit(err.Error())
	}
	defer sniffer.Close()
	sniffer.Refresh()
	fmt.Println("Closing all done")
	return
}
