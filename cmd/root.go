/*
Copyright © 2024 ASjet
*/
package cmd

import (
	"bytes"
	"os"
	"os/signal"
	"time"

	"github.com/ASjet/prism/internal/cui"
	"github.com/ASjet/prism/internal/xdp"
	"github.com/spf13/cobra"
)

var (
	xdpProg           []byte
	flagFlushInterval time.Duration
	flagPerCPUMap     bool
)

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "prism <nic>",
	Short: "Refract your network traffic like a prism.",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		obj, err := xdp.LoadAndAttach(args[0], bytes.NewReader(xdpProg), xdp.LoadModeGeneric)
		if err != nil {
			return err
		}
		defer obj.Close()

		tui, err := cui.NewGoCui()
		if err != nil {
			return err
		}

		defer func() { // Graceful exit to avoid breaking the terminal
			if err := recover(); err != nil {
				tui.Exit()
			} else {
				tui.Exit()
			}
		}()

		sig := make(chan os.Signal, 1)
		signal.Notify(sig, os.Interrupt)

		for {
			select {
			case <-sig:
				return nil
			case <-time.After(flagFlushInterval):
				m, err := obj.CountMap()
				if err != nil {
					return err
				}
				x, y := tui.WindowSize()
				tui.Render(cui.RenderTable(m, x, y))
			}
		}
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
	rootCmd.Flags().DurationVarP(&flagFlushInterval, "flush-interval", "i", time.Second, "Flush interval")
}
