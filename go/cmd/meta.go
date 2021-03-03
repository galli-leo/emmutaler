/*
Copyright © 2021 NAME HERE <EMAIL ADDRESS>

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
package cmd

import (
	"encoding/binary"
	"io"
	"io/ioutil"
	"log"
	"os"

	"github.com/galli-leo/emmutaler/fbs"
	"github.com/galli-leo/emmutaler/meta"
	flatbuffers "github.com/google/flatbuffers/go"
	"github.com/spf13/cobra"
)

var outputFile string = ""

// metaCmd represents the meta command
var metaCmd = &cobra.Command{
	Use:   "meta",
	Short: "Extract meta information from SecureROM image.",
	Long: `A longer description that spans multiple lines and likely contains examples
and usage of using your command. For example:

Cobra is a CLI library for Go that empowers applications.
This application is a tool to generate the needed files
to quickly create a Cobra application.`,
	Args: cobra.MinimumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		if len(args) > 1 && outputFile != "" {
			log.Fatalf("Cannot use output filename in combination with multiple input args!")
		}
		for _, inputFile := range args {
			if outputFile == "" {
				outputFile = inputFile + ".emmu"
			}
			processFile(inputFile, outputFile)
		}
	},
}

func processFile(inputFile string, outputFile string) {
	log.Printf("Processing file %s, writing result to %s", inputFile, outputFile)
	inFile, err := os.Open(inputFile)
	if err != nil {
		log.Fatalf("Failed to open input file %s: %v", inputFile, err)
	}
	// Interesting bits start at 0x200, so seek to there.
	_, err = inFile.Seek(0x200, io.SeekStart)
	if err != nil {
		log.Fatalf("Could not seek to 0x200, are you sure this is a valid SecureROM image?: %v", err)
	}

	info := &meta.EmbeddedInfo{}
	err = binary.Read(inFile, binary.LittleEndian, info)
	if err != nil {
		log.Fatalf("Failed to read in embedded info: %v", err)
	}
	log.Printf("Read in image: %s", info.Build.BannerS())

	builder := flatbuffers.NewBuilder(1024)

	// BuildInfo
	banner := builder.CreateString(info.Build.BannerS())
	style := builder.CreateString(info.Build.StyleS())
	tag := builder.CreateString(info.Build.TagS())
	fbs.BuildInfoStart(builder)
	fbs.BuildInfoAddBanner(builder, banner)
	fbs.BuildInfoAddStyle(builder, style)
	fbs.BuildInfoAddTag(builder, tag)
	buildInfo := fbs.BuildInfoEnd(builder)

	// LinkerMeta

	fbs.LinkerMetaStart(builder)

	// fbs.LinkerMetaAddText(builder, info.LinkerInfo.Text.ToFlatBuffer(builder))
	// fbs.LinkerMetaAddTextSize(builder, info.LinkerInfo.TextSize)
	// fbs.LinkerMetaAddDataRoStart(builder, info.LinkerInfo.DataROStart)
	// fbs.LinkerMetaAddData(builder, info.LinkerInfo.Data.ToFlatBuffer(builder))
	// fbs.LinkerMetaAddBss(builder, info.LinkerInfo.BSS.ToFlatBuffer(builder))
	// fbs.LinkerMetaAddStacks(builder, info.LinkerInfo.Stacks.ToFlatBuffer(builder))
	// fbs.LinkerMetaAddPageTables(builder, info.LinkerInfo.PageTables.ToFlatBuffer(builder))
	// fbs.LinkerMetaAddHeapGuard(builder, info.LinkerInfo.HeapGuard)
	// fbs.LinkerMetaAddBootTrampoline(builder, info.LinkerInfo.BootTrampoline.ToFlatBuffer(builder))
	// fbs.LinkerMetaAddBootTrampolineDest(builder, info.LinkerInfo.BootTrampolineDest)

	linkerMeta := fbs.LinkerMetaEnd(builder)

	fbs.ROMMetaStart(builder)
	fbs.ROMMetaAddBuildInfo(builder, buildInfo)
	fbs.ROMMetaAddLinkerInfo(builder, linkerMeta)
	romMeta := fbs.ROMMetaEnd(builder)
	builder.Finish(romMeta)
	data := builder.FinishedBytes()
	err = ioutil.WriteFile(outputFile, data, 0777)
	if err != nil {
		log.Fatalf("Failed to write output to %s: %v", outputFile, err)
	}
}

func init() {
	rootCmd.AddCommand(metaCmd)

	metaCmd.Flags().StringVarP(&outputFile, "--output", "o", "", "Path to output file, by default we will use the same name & location as the image")

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// metaCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// metaCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}
