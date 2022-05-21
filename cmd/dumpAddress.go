/*
Copyright © 2022 NAME HERE <EMAIL ADDRESS>

*/
package cmd

import (
	"fmt"
	"github.com/spf13/cobra"
)

// dumpAddressCmd represents the dumpAddress command
var dumpAddressCmd = &cobra.Command{
	Use:   "dump-address <private-key>",
	Short: "Dump address from private key",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		hrp, _ := cmd.Flags().GetString(FlagBech32Prefix)

		var privateKey = args[0]
		addr, err := buildAddressFromPrivateKey(hrp, privateKey)
		if err != nil {
			fmt.Printf("%+v\n", err)
			panic(err)
		}
		fmt.Printf("addr %v\n", addr)
	},
}

func init() {
	rootCmd.AddCommand(dumpAddressCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// dumpAddressCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// dumpAddressCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")

	AddDumpAddressFlagsToCmd(dumpAddressCmd)
}
