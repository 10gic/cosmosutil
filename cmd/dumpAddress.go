/*
Copyright © 2022 NAME HERE <EMAIL ADDRESS>

*/
package cmd

import (
	"fmt"
	"github.com/spf13/cobra"
	"github.com/tyler-smith/go-bip39"
)

// dumpAddressCmd represents the dumpAddress command
var dumpAddressCmd = &cobra.Command{
	Use:   "dump-address <private-key-or-mnemonics>",
	Short: "Dump address from private key or mnemonics",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		hrp, _ := cmd.Flags().GetString(FlagBech32Prefix)

		var err error
		var privateKeyOrMnemonic = args[0]
		var privateKey string

		if bip39.IsMnemonicValid(privateKeyOrMnemonic) {
			privateKey, err = MnemonicToPrivateKey(privateKeyOrMnemonic, "m/44'/118'/0'/0/0")
			if err != nil {
				fmt.Printf("%+v\n", err)
				panic(err)
			}
		} else {
			privateKey = privateKeyOrMnemonic
		}

		addr, err := buildAddressFromPrivateKey(hrp, privateKey)
		if err != nil {
			fmt.Printf("%+v\n", err)
			panic(err)
		}
		fmt.Printf("private key %s, addr %v\n", privateKey, addr)
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
