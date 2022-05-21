/*
Copyright © 2022 NAME HERE <EMAIL ADDRESS>

*/
package cmd

import (
	"fmt"
	"github.com/spf13/cobra"
	"log"
)

// balanceCmd represents the balance command
var balanceCmd = &cobra.Command{
	Use:   "balance <address>",
	Short: "Check balance for address",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		var addr = args[0]

		restApi, _ := cmd.Flags().GetString(FlagRestApi)
		response, err := getAllBalances(restApi, addr)
		if err != nil {
			log.Fatal(err)
			return
		}

		fmt.Printf("%s\n", response)
	},
}

func init() {
	rootCmd.AddCommand(balanceCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// balanceCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// balanceCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")

	AddBalanceFlagsToCmd(balanceCmd)
}
