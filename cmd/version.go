package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

var (
	version  = "v1.5.0"
	codename = "NahaN Core"
)

func init() {
	rootCmd.AddCommand(&cobra.Command{
		Use:   "version",
		Short: "Print current version of NahaN Core",
		Run: func(cmd *cobra.Command, args []string) {
			showVersion()
		},
	})
}

func showVersion() {
	fmt.Printf("%s %s \n", codename, version)
}
