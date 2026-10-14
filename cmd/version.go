package cmd

import (
	"encoding/json"
	"fmt"

	updater "github.com/NahaNCode/nahan-core/utility/update"
	"github.com/spf13/cobra"
)

var (
	version     = "development"
	buildCommit = "development"
	codename    = "NahaN Core"
)

func init() {
	var structured bool
	command := &cobra.Command{
		Use:   "version",
		Short: "Print current version of NahaN Core",
		Run: func(cmd *cobra.Command, args []string) {
			if structured {
				json.NewEncoder(cmd.OutOrStdout()).Encode(map[string]string{"version": version, "commit": buildCommit, "digest": updater.RunningDigest()})
				return
			}
			showVersion()
		},
	}
	command.Flags().BoolVar(&structured, "json", false, "Print running build identity as JSON")
	rootCmd.AddCommand(command)
}

func showVersion() {
	fmt.Printf("%s %s \n", codename, version)
}
