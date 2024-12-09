package cmd

import (
	"fmt"
	"os"

	"github.com/ezrantn/cercle/internal"
	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "cercle",
	Short: "SSL Certificate Analysis Tool",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		outputFile, _ := cmd.Flags().GetString("output")
		outputFormat := "text"
		if outputFile != "" {
			if len(outputFile) > 5 && outputFile[len(outputFile)-5:] == ".json" {
				outputFormat = "json"
			} else if len(outputFile) > 5 && outputFile[len(outputFile)-5:] == ".yaml" {
				outputFormat = "yaml"
			}
		}

		config := internal.LoadConfig()
		config.OutputFormat = outputFormat
		config.OutputFile = outputFile

		hostname := args[0]
		port, _ := cmd.Flags().GetString("port")

		analysis, err := internal.AnalyzeCertificate(hostname, port, config)
		if err != nil {
			fmt.Printf("Certificate analysis failed\n hostname=%s\nerror=%s", hostname, err.Error())
			os.Exit(1)
		}

		if err := internal.OutputResults(analysis, config); err != nil {
			fmt.Printf("Failed to output results: %s", err.Error())
			os.Exit(1)
		}
	},
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func init() {
	rootCmd.AddCommand(versionCmd)
	rootCmd.Flags().StringP("output", "o", "text", "Output format (text/json/yaml)")
	rootCmd.Flags().StringP("port", "p", "443", "Port to check")
	rootCmd.Flags().Bool("insecure", false, "Skip certificate verification")
}
