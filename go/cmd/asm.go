package cmd

import (
	"log"

	"github.com/spf13/cobra"
)

var doPatch bool

// asmCmd represents the asm command
var asmCmd = &cobra.Command{
	Use:   "asm",
	Short: "Generates the rom.S file.",
	Long:  `TODO`,
	Run: func(cmd *cobra.Command, args []string) {
		err := r.BuildChunks()
		if err != nil {
			log.Fatalf("Failed to build chunks: %s", err)
		}
		if doPatch {
			err = r.BuildInstructionDB()
			if err != nil {
				log.Fatalf("Failed to build instruction db: %s", err)
			}
			r.DoPatch()
		}
		err = r.GenerateTemplate("rom.S", outputDirectory)
		if err != nil {
			log.Fatalf("Failed to generate asm: %s", err)
		}
	},
}

func init() {
	romCmd.AddCommand(asmCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// asmCmd.PersistentFlags().String("foo", "", "A help for foo")
	asmCmd.PersistentFlags().BoolVarP(&doPatch, "patch", "p", true, "Whether the rom image should be ran through the patcher before generating the .S file.")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// asmCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}
