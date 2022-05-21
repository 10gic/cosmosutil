package cmd

import (
	"fmt"
	"github.com/spf13/cobra"
	"strconv"
)

/// Modify from: https://github.com/cosmos/cosmos-sdk/blob/v0.45.4/client/flags/flags.go

const (
	// DefaultGasAdjustment is applied to gas estimates to avoid tx execution
	// failures due to state changes that might occur between the tx simulation
	// and the actual run.
	DefaultGasAdjustment = 1.0
	DefaultGasLimit      = 200000
	GasFlagAuto          = "auto"

	// BroadcastBlock defines a tx broadcasting mode where the client waits for
	// the tx to be committed in a block.
	BroadcastBlock = "block"
	// BroadcastSync defines a tx broadcasting mode where the client waits for
	// a CheckTx execution response only.
	BroadcastSync = "sync"
	// BroadcastAsync defines a tx broadcasting mode where the client returns
	// immediately.
	BroadcastAsync = "async"
)

const (
	//FlagUseLedger     = "ledger"
	//FlagChainID       = "chain-id"
	//FlagNode          = "node"
	//FlagHeight        = "height"
	//FlagGasAdjustment = "gas-adjustment"
	//FlagFrom          = "from"
	//FlagAccountNumber = "account-number"
	//FlagSequence      = "sequence"
	FlagFees          = "fees"
	FlagGasLimit      = "gas-limit"
	FlagGasPrices     = "gas-prices"
	FlagBroadcastMode = "broadcast-mode"
	FlagDryRun        = "dry-run"
	FlagGenerateOnly  = "generate-only"
	FlagOffline       = "offline"
	FlagSignMode      = "sign-mode"
	FlagTimeoutHeight = "timeout-height"
	FlagPrivateKey    = "private-key"
	FlagMemo          = "memo"
	FlagRestApi       = "rest-api"
	FlagBech32Prefix  = "bech32-prefix"
)

// AddTransferFlagsToCmd adds common flags to a module tx command.
func AddTransferFlagsToCmd(cmd *cobra.Command) {
	// cmd.Flags().Uint64P(FlagAccountNumber, "a", 0, "The account number of the signing account (offline mode only)")
	// cmd.Flags().Uint64P(FlagSequence, "s", 0, "The sequence number of the signing account (offline mode only)")
	cmd.Flags().String(FlagFees, "1200uatom", "Fees to pay along with transaction; eg: 10uatom")
	// cmd.Flags().String(FlagGasPrices, "", "Gas prices in decimal format to determine the transaction fee (e.g. 0.1uatom)")
	cmd.Flags().String(FlagRestApi, "https://api.cosmos.network", "REST api for this chain, cosmos based chain api can found in https://github.com/cosmos/chain-registry")
	// cmd.Flags().Float64(FlagGasAdjustment, DefaultGasAdjustment, "adjustment factor to be multiplied against the estimate returned by the tx simulation; if the gas limit is set manually this flag is ignored ")
	// cmd.Flags().StringP(FlagBroadcastMode, "b", BroadcastSync, "Transaction broadcasting mode (sync|async|block)")
	// cmd.Flags().Bool(FlagDryRun, false, "ignore the --gas flag and perform a simulation of a transaction, but don't broadcast it")
	// cmd.Flags().Bool(FlagGenerateOnly, false, "Build an unsigned transaction and write it to STDOUT (when enabled, the local Keybase is not accessible)")
	// cmd.Flags().Bool(FlagOffline, false, "Offline mode (does not allow any online functionality")
	// cmd.Flags().Uint64(FlagTimeoutHeight, 0, "Set a block timeout height to prevent the tx from being committed past a certain height")
	cmd.Flags().String(FlagPrivateKey, "", "Private key of signer")
	cmd.Flags().String(FlagBech32Prefix, "cosmos", "Bech32 human-readable part")

	// --gas can accept integers and "auto"
	cmd.Flags().String(FlagGasLimit, "", fmt.Sprintf("gas limit to set per-transaction; set to %q to calculate sufficient gas automatically (default %d)", GasFlagAuto, DefaultGasLimit))

	cmd.MarkFlagRequired(FlagPrivateKey)
}

func AddDumpAddressFlagsToCmd(cmd *cobra.Command) {
	cmd.Flags().String(FlagBech32Prefix, "cosmos", "Bech32 human-readable part")
}

func AddBalanceFlagsToCmd(cmd *cobra.Command) {
	cmd.Flags().String(FlagRestApi, "https://api.cosmos.network", "REST api for this chain, cosmos based chain api can found in https://github.com/cosmos/chain-registry")
}

// GasSetting encapsulates the possible values passed through the --gas flag.
type GasSetting struct {
	Simulate bool
	Gas      uint64
}

func (v *GasSetting) String() string {
	if v.Simulate {
		return GasFlagAuto
	}

	return strconv.FormatUint(v.Gas, 10)
}

// ParseGasSetting parses a string gas value. The value may either be 'auto',
// which indicates a transaction should be executed in simulate mode to
// automatically find a sufficient gas value, or a string integer. It returns an
// error if a string integer is provided which cannot be parsed.
func ParseGasSetting(gasStr string) (GasSetting, error) {
	switch gasStr {
	case "":
		return GasSetting{false, DefaultGasLimit}, nil

	case GasFlagAuto:
		return GasSetting{true, 0}, nil

	default:
		gas, err := strconv.ParseUint(gasStr, 10, 64)
		if err != nil {
			return GasSetting{}, fmt.Errorf("gas must be either integer or %s", GasFlagAuto)
		}

		return GasSetting{false, gas}, nil
	}
}
