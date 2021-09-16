package cmd

import (
	"log"

	usbmsg "github.com/galli-leo/emmutaler/usb_msg"
	"github.com/spf13/cobra"
)

var msgOutDir string
var msgImgDir string

// usbMsgCmd represents the usbMsg command
var usbMsgCmd = &cobra.Command{
	Use:   "usb",
	Short: "Generate USB message files",
	Long:  `Generate example USB message files as inputs for fuzzers.`,
	Run: func(cmd *cobra.Command, args []string) {
		gen := usbmsg.NewGen(msgOutDir, msgImgDir)
		e := gen.Gen()
		if e != nil {
			log.Fatalf("Failed to generate messages: %s", e)
		}
	},
}

func init() {
	rootCmd.AddCommand(usbMsgCmd)

	usbMsgCmd.Flags().StringVarP(&msgOutDir, "out", "o", "../../usb_msg", "Output directory for the generated USB message sequences")
	/// TODO: Maybe we should generate them ad hoc instead?
	usbMsgCmd.Flags().StringVarP(&msgImgDir, "img", "i", "../../img", "Output directory where generated images are located. Some message sequences use generated images.")

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// usbMsgCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// usbMsgCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}
