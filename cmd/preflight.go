package cmd

import (
	"encoding/json"
	"errors"
	"io"
	"os"

	"github.com/NahaNCode/nahan-core/utility/entryprofile"
	"github.com/spf13/cobra"
)

func init() {
	var filename string
	command := &cobra.Command{
		Use: "entry-preflight", Short: "Validate an Xray entry without starting a listener", Args: cobra.NoArgs,
		SilenceUsage: true, SilenceErrors: true,
		RunE: func(command *cobra.Command, args []string) error {
			var input io.Reader = command.InOrStdin()
			if filename != "-" {
				file, err := os.Open(filename)
				if err != nil {
					return errors.New("cannot read entry file")
				}
				defer file.Close()
				input = file
			}
			data, err := io.ReadAll(io.LimitReader(input, entryprofile.MaxBytes+1))
			if err != nil {
				return errors.New("cannot read entry document")
			}
			result := entryprofile.Preflight(data)
			if err := json.NewEncoder(command.OutOrStdout()).Encode(result); err != nil {
				return err
			}
			if !result.Valid {
				return errors.New("entry preflight rejected")
			}
			return nil
		},
	}
	command.Flags().StringVar(&filename, "file", "-", "Entry JSON path, or - for stdin")
	rootCmd.AddCommand(command)
}
