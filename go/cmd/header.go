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
	"log"

	"github.com/spf13/cobra"
)

// headerCmd represents the header command
var headerCmd = &cobra.Command{
	Use:   "header",
	Short: "Generate the c header for the rom image.",
	Long:  `Generates the c header for the given rom image. The header will contain all found symbol definition including their types.`,
	Run: func(cmd *cobra.Command, args []string) {
		err := r.GenerateTemplate("rom.h", outputDirectory)
		if err != nil {
			log.Fatalf("Failed to generate header: %v", err)
		}
	},
}

var symHeaderCmd = &cobra.Command{
	Use:   "symh",
	Short: "Generate the c header for the rom symbols.",
	Long:  `Generates the c header for the given rom image's symbols. This is used for debugging exclusively.`,
	Run: func(cmd *cobra.Command, args []string) {
		err := r.GenerateTemplate("symbols_list.h", outputDirectory)
		if err != nil {
			log.Fatalf("Failed to generate header: %v", err)
		}
	},
}

var configHeaderCmd = &cobra.Command{
	Use:   "configh",
	Short: "Generate the c config header.",
	Long:  `TODO`,
	Run: func(cmd *cobra.Command, args []string) {
		err := r.GenerateTemplate("config.h", outputDirectory)
		if err != nil {
			log.Fatalf("Failed to generate header: %v", err)
		}
	},
}

func init() {
	romCmd.AddCommand(headerCmd)
	romCmd.AddCommand(symHeaderCmd)
	romCmd.AddCommand(configHeaderCmd)
	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// headerCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// headerCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}
