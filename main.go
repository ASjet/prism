/*
Copyright © 2024 ASjet
*/
package main

import (
	_ "embed"

	"github.com/ASjet/prism/cmd"
)

//go:generate make -C ./xdp prism.o
//go:embed xdp/prism.o
var prismXdpProg []byte

func main() {
	cmd.Execute(prismXdpProg)
}
