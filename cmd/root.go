/*
Copyright © 2024 ASjet
*/
package cmd

import (
	"bytes"
	"fmt"
	"os"
	"os/signal"
	"time"

	"github.com/ASjet/prism/internal/util"
	"github.com/ASjet/prism/internal/xdp"
	"github.com/spf13/cobra"
)

var (
	xdpProg           []byte
	flagFlushInterval time.Duration
	flagPerCPUMap     bool
	flagAppProto      bool
)

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "prism <nic ...>",
	Short: "Display network traffic components like a prism",
	Args:  cobra.MinimumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		xdp, err := xdp.LoadAndAttach(args[0], bytes.NewReader(xdpProg), xdp.LoadModeGeneric)
		if err != nil {
			return err
		}
		defer xdp.Close()

		go printCount(xdp)

		sig := make(chan os.Signal, 1)
		signal.Notify(sig, os.Interrupt)
		<-sig
		return nil
	},
}

func Execute(prog []byte) {
	xdpProg = prog
	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}

func init() {
	// TODO: switch to per-CPU hash map
	rootCmd.Flags().BoolVar(&flagPerCPUMap, "per-cpu", false, "Use per-CPU hash map")
	// TODO: add support for application layer protocol
	rootCmd.Flags().BoolVar(&flagAppProto, "app", false, "Parse application layer protocol")
	rootCmd.Flags().DurationVarP(&flagFlushInterval, "flush-interval", "i", time.Second, "Flush interval")
}

// TODO: render a pretty table in a rich CUI
func printCount(obj *xdp.XDP) {
	for range time.Tick(flagFlushInterval) {
		fmt.Println(time.Now())
		pktCnt, err := obj.PktCountMap()
		if err != nil {
			fmt.Println(err)
			return
		}
		byteCnt, err := obj.ByteCountMap()
		if err != nil {
			fmt.Println(err)
			return
		}
		for k, v := range byteCnt {
			fmt.Printf("%v: %s(%d)\n", k.Protocols(), util.ReadableSize(v), pktCnt[k])
		}
	}
}
