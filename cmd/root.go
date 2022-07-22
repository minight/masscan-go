package cmd

import (
	"github.com/minight/masscan-go/pkg/convert"
	"github.com/minight/masscan-go/pkg/masscan"
	"os"

	c "github.com/minight/masscan-go/internal/cmd"
	"github.com/spf13/cobra"
)

var (
	loglevel  string = "info"
	logformat string = "pretty"
	input     string = "-"
	ports     []uint = convert.ConvertSlice[uint16, uint](masscan.DefaultPorts)
)

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "masscan-go",
	Short: "port scan very fast",
	Long: `a go implementation of masscan. only does tcp syn scans
only works on *nix systems. No banners. just fast tcp scans`,
	Run: func(cmd *cobra.Command, args []string) {
		c.Run(loglevel, logformat, input, ports)
	},
}

func Execute() {
	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}

func init() {
	rootCmd.Flags().StringVarP(&loglevel, "loglevel", "v", loglevel, "Log level: trace,debug,info,error")
	rootCmd.Flags().StringVarP(&logformat, "logformat", "o", logformat, "Log format: json,pretty,text")
	rootCmd.Flags().StringVarP(&input, "input", "i", input, "input file. if its - then we read from stdin")
	rootCmd.Flags().UintSliceVarP(&ports, "ports", "p", ports, "ports to scan for")
}
