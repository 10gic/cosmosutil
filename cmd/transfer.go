/*
Copyright © 2022 NAME HERE <EMAIL ADDRESS>

*/
package cmd

import (
	"encoding/base64"
	"fmt"
	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/cosmos/cosmos-sdk/x/bank/types"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

// transferCmd represents the transfer command
var transferCmd = &cobra.Command{
	Use:   "transfer <to-address> <coin>",
	Short: "Transfer coin to address",
	Args:  cobra.ExactArgs(2),
	Run: func(cmd *cobra.Command, args []string) {
		toAddress := args[0]
		coin := args[1]

		txJson, tx, err := buildMsgSendTx(toAddress,
			coin,
			cmd.Flags())
		if err != nil {
			fmt.Printf("%+v\n", err)
			panic(err)
		}

		fmt.Printf("The tx is:\n%v\n\n", txJson)
		base64Tx := base64.StdEncoding.EncodeToString(tx)

		restApi, _ := cmd.Flags().GetString(FlagRestApi)
		fmt.Printf("Please run following command to broadcast the tx:\ncurl '%s/cosmos/tx/v1beta1/txs' -d '{\"tx_bytes\": \"%s\", \"mode\": \"BROADCAST_MODE_BLOCK\"}'\n",
			restApi, base64Tx)
	},
}

func buildMsgSendTx(toAddr string, transferCoin string, flagSet *pflag.FlagSet) (string, []byte, error) {
	privateKey, _ := flagSet.GetString(FlagPrivateKey)
	memo, _ := flagSet.GetString(FlagMemo)
	restApi, _ := flagSet.GetString(FlagRestApi)
	hrp, _ := flagSet.GetString(FlagBech32Prefix)
	fee, _ := flagSet.GetString(FlagFees)

	fromAddr, err := buildAddressFromPrivateKey(hrp, privateKey)
	if err != nil {
		return "", nil, err
	}

	coins, err := sdk.ParseCoinsNormalized(transferCoin)
	if err != nil {
		return "", nil, err
	}

	msg := &types.MsgSend{FromAddress: fromAddr, ToAddress: toAddr, Amount: coins}

	chainId, err := getChainId(restApi)
	if err != nil {
		return "", nil, fmt.Errorf("getChainId fail: %w", err)
	}

	accountNumber, sequence, err := getAccountInfo(restApi, fromAddr)

	feeCoin, err := sdk.ParseCoinsNormalized(fee)
	if err != nil {
		return "", nil, err
	}
	feeCoinDenom := feeCoin[0].Denom
	feeCoinAmount := feeCoin[0].Amount.Int64()

	gasLimitStr, _ := flagSet.GetString(FlagGasLimit)
	gasSetting, _ := ParseGasSetting(gasLimitStr)
	var gasLimit uint64
	if gasSetting.Simulate {
		gasLimit, err = estimateGasLimit(restApi, sequence, memo, feeCoinDenom, feeCoinAmount, msg)
		if err != nil {
			return "", nil, fmt.Errorf("estimateGasLimit fail: %w", err)
		}
	} else {
		gasLimit = gasSetting.Gas
	}

	return buildTx(privateKey, chainId, accountNumber, sequence, memo, feeCoinDenom, feeCoinAmount, gasLimit, msg)
}

func init() {
	rootCmd.AddCommand(transferCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// transferCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// transferCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")

	AddTransferFlagsToCmd(transferCmd)
}
