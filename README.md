# cosmosutil
A cosmos util, can transfer coin, check balance etc

# Usage Example
## Check Balance
Check balance of an address:
```
$ cosmosutil balance cosmos1slz7v8lrtn79f0xgngg7e6cmw56ms56els8rrl
{
  "balances": [
    {
      "denom": "ibc/F5ED5F3DC6F0EF73FA455337C027FE91ABCB375116BF51A228E44C493E020A09",
      "amount": "44000000000000000000"
    },
    {
      "denom": "uatom",
      "amount": "168793"
    }
  ],
  "pagination": {
    "next_key": null,
    "total": "2"
  }
}
```

## Transfer ATOM
Transfer ATOM to an address:
```
$ cosmosutil transfer cosmos1krxe7dqswsqv078wmrx6d80xx9l64lft7qtz83  10uatom --private-key 0x96adc457e360fb138fab007df9153f9145df8fc1ea05bc417fd2693703c7ecb7
The tx is:
{"body":{"messages":[{"@type":"/cosmos.bank.v1beta1.MsgSend","from_address":"cosmos1krxe7dqswsqv078wmrx6d80xx9l64lft7qtz83","to_address":"cosmos1krxe7dqswsqv078wmrx6d80xx9l64lft7qtz83","amount":[{"denom":"uatom","amount":"10"}]}],"memo":"","timeout_height":"0","extension_options":[],"non_critical_extension_options":[]},"auth_info":{"signer_infos":[{"public_key":{"@type":"/cosmos.crypto.secp256k1.PubKey","key":"AjGgb2PRz2AZ433fd3wqbfzVQCtveVmlhNqPUi6qRGz8"},"mode_info":{"single":{"mode":"SIGN_MODE_DIRECT"}},"sequence":"0"}],"fee":{"amount":[{"denom":"uatom","amount":"1200"}],"gas_limit":"200000","payer":"","granter":""}},"signatures":["go5gN2xCd0b4yh5ibOkX4DIz10SOAjWyPp8o5AGA3ysIlv/ntALTUTzZFzGmLMmeqD/or/bga3HVOMh4QXRctg=="]}

Please run following command to broadcast the tx:
curl 'https://api.cosmos.network/cosmos/tx/v1beta1/txs' -d '{"tx_bytes": "Co4BCosBChwvY29zbW9zLmJhbmsudjFiZXRhMS5Nc2dTZW5kEmsKLWNvc21vczFrcnhlN2Rxc3dzcXYwNzh3bXJ4NmQ4MHh4OWw2NGxmdDdxdHo4MxItY29zbW9zMWtyeGU3ZHFzd3NxdjA3OHdtcng2ZDgweHg5bDY0bGZ0N3F0ejgzGgsKBXVhdG9tEgIxMBJlCk4KRgofL2Nvc21vcy5jcnlwdG8uc2VjcDI1NmsxLlB1YktleRIjCiECMaBvY9HPYBnjfd93fCpt/NVAK295WaWE2o9SLqpEbPwSBAoCCAESEwoNCgV1YXRvbRIEMTIwMBDAmgwaQIKOYDdsQndG+MoeYmzpF+AyM9dEjgI1sj6fKOQBgN8rCJb/57QC01E82RcxpizJnqg/6K/24Gtx1TjIeEF0XLY=", "mode": "BROADCAST_MODE_BLOCK"}'
```

## Dump Address
Dump address from a private key:
```
$ cosmosutil dump-address 0x96adc457e360fb138fab007df9153f9145df8fc1ea05bc417fd2693703c7ecb7
addr cosmos1krxe7dqswsqv078wmrx6d80xx9l64lft7qtz83
```

# Install
```
GO111MODULE=on go install github.com/10gic/cosmosutil@latest
```
