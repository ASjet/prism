/*
Copyright © 2024 ASjet
*/
package main

import (
	_ "embed"
	"log"

	"github.com/ASjet/prism/cmd"
	"github.com/cilium/ebpf/rlimit"
)

//go:generate make -C ./xdp prism.o
//go:embed xdp/prism.o
var prismXdpProg []byte

func main() {
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal("prism: remove rlimit.memlock error: ", err)
	}

	cmd.Execute(prismXdpProg)
}
