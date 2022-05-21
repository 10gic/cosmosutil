package cmd

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/cosmos/btcutil/bech32"
	codectypes "github.com/cosmos/cosmos-sdk/codec/types"
	"github.com/cosmos/cosmos-sdk/crypto/keys/secp256k1"
	"github.com/cosmos/cosmos-sdk/server/rosetta"
	sdk "github.com/cosmos/cosmos-sdk/types"
	txtypes "github.com/cosmos/cosmos-sdk/types/tx"
	signingtypes "github.com/cosmos/cosmos-sdk/types/tx/signing"
	authtx "github.com/cosmos/cosmos-sdk/x/auth/tx"
	"golang.org/x/crypto/ripemd160"
	"io/ioutil"
	"net/http"
	"strconv"
	"strings"
)

/// estimateGasLimit estimates gas limit
func estimateGasLimit(
	restApi string,
	sequence uint64,
	memo string,
	feeCoinDenom string,
	feeCoinAmount int64,
	msgs ...sdk.Msg,
) (uint64, error) {

	_, tx, err := buildSimTx(sequence, memo, feeCoinDenom, feeCoinAmount, msgs...)
	if err != nil {
		return 0, nil
	}

	response, err := postSimulateTx(restApi, tx)
	if err != nil {
		return 0, err
	}

	type ResponseJson struct {
		GasInfo struct {
			GasUsed string `json:"gas_used"`
		} `json:"gas_info"`
	}

	var res ResponseJson
	err = json.Unmarshal([]byte(response), &res)
	if err != nil {
		return 0, err
	}

	return strconv.ParseUint(res.GasInfo.GasUsed, 10, 64)
}

// buildSimTx creates an unsigned tx with an empty single signature and returns
// the encoded transaction or an error if the unsigned transaction cannot be
// built.
func buildSimTx(
	sequence uint64,
	memo string,
	feeCoinDenom string,
	feeCoinAmount int64,
	msgs ...sdk.Msg,
) (string, []byte, error) {

	protoCodec, _ := rosetta.MakeCodec()

	// Create an empty signature
	sig := signingtypes.SignatureV2{
		PubKey: &secp256k1.PubKey{},
		Data: &signingtypes.SingleSignatureData{
			SignMode: signingtypes.SignMode_SIGN_MODE_DIRECT,
		},
		Sequence: sequence,
	}

	txConfig := authtx.NewTxConfig(protoCodec, authtx.DefaultSignModes)
	txBuilder := txConfig.NewTxBuilder()
	err := txBuilder.SetMsgs(msgs...)
	if err != nil {
		return "", nil, err
	}
	err = txBuilder.SetSignatures(sig)
	if err != nil {
		return "", nil, err
	}

	feeAmount := sdk.NewCoins(sdk.NewInt64Coin(feeCoinDenom, feeCoinAmount))
	txBuilder.SetFeeAmount(feeAmount)
	txBuilder.SetMemo(memo)

	encodedJsonTx, err := txConfig.TxJSONEncoder()(txBuilder.GetTx())
	if err != nil {
		return "", nil, err
	}

	encodedTx, err := txConfig.TxEncoder()(txBuilder.GetTx())
	if err != nil {
		return "", nil, err
	}

	return string(encodedJsonTx), encodedTx, nil
}

/// buildTx creates a signed tx
func buildTx(
	senderPrivateKey string,
	chainId string,
	accountNumber uint64,
	sequence uint64,
	memo string,
	feeCoinDenom string,
	feeCoinAmount int64,
	gasLimit uint64,
	msgs ...sdk.Msg,
) (string, []byte, error) {
	protoCodec, _ := rosetta.MakeCodec()

	privateKey, err := buildPrivateKey(senderPrivateKey)
	if err != nil {
		return "", nil, fmt.Errorf("convert public key to type any fail: %w", err)
	}

	publicKeyTypeAny, err := codectypes.NewAnyWithValue(privateKey.PubKey())
	if err != nil {
		return "", nil, fmt.Errorf("convert public key to type any fail: %w", err)
	}

	var signerInfo []*txtypes.SignerInfo
	signerInfo = append(signerInfo, &txtypes.SignerInfo{
		PublicKey: publicKeyTypeAny,
		ModeInfo: &txtypes.ModeInfo{
			Sum: &txtypes.ModeInfo_Single_{
				Single: &txtypes.ModeInfo_Single{
					Mode: signingtypes.SignMode_SIGN_MODE_DIRECT,
				},
			},
		},
		Sequence: sequence,
	})

	feeAmount := sdk.NewCoins(sdk.NewInt64Coin(feeCoinDenom, feeCoinAmount))
	fee := txtypes.Fee{Amount: feeAmount, GasLimit: gasLimit}
	authInfo := &txtypes.AuthInfo{
		Fee:         &fee,
		SignerInfos: signerInfo,
	}
	authInfoBytes := protoCodec.MustMarshal(authInfo)

	anys := make([]*codectypes.Any, len(msgs))
	for i, msg := range msgs {
		anys[i], err = codectypes.NewAnyWithValue(msg)
	}
	if err != nil {
		return "", nil, fmt.Errorf("convert msg to type any fail: %w", err)
	}
	txBody := &txtypes.TxBody{
		Memo:     memo,
		Messages: anys,
	}
	bodyBytes := protoCodec.MustMarshal(txBody)

	signDoc := txtypes.SignDoc{
		AccountNumber: accountNumber,
		AuthInfoBytes: authInfoBytes,
		BodyBytes:     bodyBytes,
		ChainId:       chainId,
	}

	signBytes, err := signDoc.Marshal()
	if err != nil {
		return "", nil, fmt.Errorf("marshaly signDoc fail: %w", err)
	}
	// Sign the data
	signature, err := privateKey.Sign(signBytes)
	if err != nil {
		return "", nil, fmt.Errorf("sign fail: %w", err)
	}
	sigData := &signingtypes.SingleSignatureData{
		SignMode:  signingtypes.SignMode_SIGN_MODE_DIRECT,
		Signature: signature,
	}

	sig := signingtypes.SignatureV2{
		PubKey:   privateKey.PubKey(),
		Data:     sigData,
		Sequence: signerInfo[0].Sequence,
	}

	txConfig := authtx.NewTxConfig(protoCodec, authtx.DefaultSignModes)
	txBuilder := txConfig.NewTxBuilder()
	err = txBuilder.SetMsgs(msgs...)
	if err != nil {
		return "", nil, err
	}
	err = txBuilder.SetSignatures(sig)
	if err != nil {
		return "", nil, err
	}
	txBuilder.SetFeeAmount(feeAmount)
	txBuilder.SetGasLimit(gasLimit)
	txBuilder.SetMemo(memo)

	encodedJsonTx, err := txConfig.TxJSONEncoder()(txBuilder.GetTx())
	if err != nil {
		return "", nil, err
	}

	encodedTx, err := txConfig.TxEncoder()(txBuilder.GetTx())
	if err != nil {
		return "", nil, err
	}

	return string(encodedJsonTx), encodedTx, nil
}

/// buildPrivateKey builds secp256k1.PrivKey from private key hex string
func buildPrivateKey(privateKeyHex string) (*secp256k1.PrivKey, error) {
	if strings.HasPrefix(privateKeyHex, "0x") {
		privateKeyHex = privateKeyHex[2:] // remove leading 0x
	}
	privateKeyBytes, err := hex.DecodeString(privateKeyHex)
	if err != nil {
		return nil, fmt.Errorf("hex decode private key fail: %w", err)
	}
	privateKey := &secp256k1.PrivKey{
		Key: privateKeyBytes,
	}
	return privateKey, nil
}

/// buildAddressFromPrivateKey builds address from private key hex string
/// https://docs.cosmos.network/master/architecture/adr-028-public-key-addresses.html#legacy-public-key-addresses-don-t-change
func buildAddressFromPrivateKey(hrp, privateKeyHex string) (string, error) {
	if strings.HasPrefix(privateKeyHex, "0x") {
		privateKeyHex = privateKeyHex[2:] // remove leading 0x
	}

	privateKeyBytes, err := hex.DecodeString(privateKeyHex)
	if err != nil {
		return "", err
	}
	privateKey := secp256k1.PrivKey{
		Key: privateKeyBytes,
	}
	compressedPublicKeyBytes := privateKey.PubKey().Bytes()

	h1 := sha256.New()
	h1.Write(compressedPublicKeyBytes)

	h2 := ripemd160.New()
	h2.Write(h1.Sum(nil))
	sha256Ripemd160 := h2.Sum(nil)

	return bech32.EncodeFromBase256(hrp, sha256Ripemd160)
}

func httpGet(url string) ([]byte, error) {
	return httpRequest("GET", url, nil)
}

func httpPost(url string, body []byte) ([]byte, error) {
	return httpRequest("POST", url, body)
}

func httpRequest(method string, url string, body []byte) ([]byte, error) {
	httpClient := http.DefaultClient
	httpReq, err := http.NewRequest(method, url, bytes.NewReader(body))

	httpRes, err := httpClient.Do(httpReq)
	if err != nil {
		return nil, err
	}
	defer httpRes.Body.Close()

	httpResBytes, err := ioutil.ReadAll(httpRes.Body)
	if err != nil {
		return nil, err
	}
	return httpResBytes, nil
}

func getChainId(restApi string) (string, error) {
	response, err := httpRequest("GET", fmt.Sprintf("%s/node_info", restApi), nil)
	if err != nil {
		return "", err
	}

	type ResponseJson struct {
		NodeInfo struct {
			Network string `json:"network"`
		} `json:"node_info"`
	}

	var res ResponseJson
	err = json.Unmarshal(response, &res)
	if err != nil {
		return "", err
	}

	return res.NodeInfo.Network, nil
}

func getAccountInfo(restApi string, address string) (accountNumber uint64, sequence uint64, err error) {
	response, err := httpGet(fmt.Sprintf("%s/cosmos/auth/v1beta1/accounts/%s", restApi, address))
	if err != nil {
		return 0, 0, err
	}

	type ResponseJson struct {
		Account struct {
			AccountNumber string `json:"account_number"`
			Sequence      string `json:"sequence"`
		} `json:"account"`
	}

	var res ResponseJson
	err = json.Unmarshal(response, &res)
	if err != nil {
		return 0, 0, err
	}

	accountNumber, err = strconv.ParseUint(res.Account.AccountNumber, 10, 64)
	if err != nil {
		return 0, 0, err
	}

	sequence, err = strconv.ParseUint(res.Account.Sequence, 10, 64)
	if err != nil {
		return 0, 0, err
	}
	return accountNumber, sequence, nil
}

func getAllBalances(restApi string, address string) (string, error) {
	response, err := httpGet(fmt.Sprintf("%s/cosmos/bank/v1beta1/balances/%s", restApi, address))
	if err != nil {
		return "", err
	}

	var prettyJSON bytes.Buffer
	err = json.Indent(&prettyJSON, response, "", "  ")
	if err != nil {
		return "", err
	}

	return string(prettyJSON.Bytes()), nil
}

func postSimulateTx(restApi string, tx []byte) (string, error) {
	data := fmt.Sprintf("{\"tx_bytes\": \"%s\"}", base64.StdEncoding.EncodeToString(tx))
	response, err := httpPost(fmt.Sprintf("%s/cosmos/tx/v1beta1/simulate", restApi), []byte(data))
	if err != nil {
		return "", err
	}

	var prettyJSON bytes.Buffer
	err = json.Indent(&prettyJSON, response, "", "  ")
	if err != nil {
		return "", err
	}

	return string(prettyJSON.Bytes()), nil
}
