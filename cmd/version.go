package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print the version number of Cercle",
	Long:  `All software has versions. This is Cercle's`,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("0.0.1")
	},
}
