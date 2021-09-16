package cmd

import (
	"log"
	"os"
	"runtime/pprof"

	"github.com/galli-leo/emmutaler/img"
	"github.com/spf13/cobra"
)

var certDir string
var outDir string
var cpuProfile string

// imgCmd represents the img command
var imgCmd = &cobra.Command{
	Use:   "img",
	Short: "Generate valid *OS img4 file.",
	Long:  `Tool to generate valid *OS img4 files. See subcommands for more info. Currently the main tool tries to parse an input image.`,
	// Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		if cpuProfile != "" {
			f, err := os.Create(cpuProfile)
			if err != nil {
				log.Fatal(err)
			}
			pprof.StartCPUProfile(f)
			defer pprof.StopCPUProfile()
		}
		img.GenerateImages(outDir, certDir)
	},
}

func init() {
	rootCmd.AddCommand(imgCmd)
	imgCmd.PersistentFlags().StringVarP(&certDir, "certs", "c", "../../certs", "Directory where to store / read certificates from.")
	imgCmd.Flags().StringVarP(&outDir, "out", "o", "../../img", "Directory where to output images to.")
	imgCmd.Flags().StringVarP(&cpuProfile, "profile", "p", "", "Path to cpu profile")
	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// imgCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// imgCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}
