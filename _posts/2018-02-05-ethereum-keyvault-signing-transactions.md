---
layout: post
title: Ethereum and Azure Key Vault - Part 2
subtitle: Signing offline transactions
bigimg: /img/Image-2-17-18-10.20.jpg
tags: [ethereum, azure-keyvault, f#]
social-share: false
---
>
This is the second part of the article series of interacting with Ethereum blockchain by securing keys in Azure Key Vault. This part deals with creating, signing and sending offline transactions. If you haven’t yet, check out [Part 1](/2018-01-31-ethereum-keyvault-generating-keys) which deals with key management and generating addresses.
>
[The full F# source code for both articles is available on GitHub.](https://github.com/tmarkovski/ethereum-key-vault)

---
## Part 2: Sending transactions
In order to be able to send transactions to the blockchain and use external key management source (not part of the Web3 or Geth tools) we can send raw transactions. These transactions are already signed, so they can be sent directly to the chain. Best way to test this transactions is to setup a local node using geth for testing purposes. Make sure to run the node with RPC enabled, so you can send the transactions directly from the F# project. I use the following command to start my node.

`geth --datadir ~/.eth_test/ --maxpeers 0 --nodiscover --rpc console`

Otherwise, you can simply send the transaction by sending it to the geth console using `eth.sendRawTransaction(trasnactionHash)`.

This sample code uses Bouncy Castle and Nethereum libraries for .NET standard. Nethereum is a great library to work with Ethereum, but unfortunately it doesn’t support signing transactions outside of a running node, so we’ll just use it for some of the utility classes for serializing data using RLP.

The process of creating an offline transaction for Ethereum is done in the following steps

- Create a transaction object (receiver, amount, nonce)
- Serialize and hash the transaction with Keccak 256
- Sign the hashed message using Key Vault
- Serialize the original message and the signed message

### Create transaction object
Creating the transaction data is very straightforward. At the minimum, we need the receivers address, the amount to send and the nonce. The nonce is very important, sending an incorrect nonce will either be rejected or the transaction may be discarded by the miners. Fortunately, figuring out what the nonce is pretty easy. In essence it’s a transaction counter used to prevent replay attacks. To see what nonce you need to set for a certain transaction, simply get the transaction count for the sender’s address. For example, if Alice wants to send funds to Bob, we can find the total transactions for Alice using geth eth.getTransactionCount("Alice's address") or the wrapper classes in the sample project that uses RPC.

Let’s create a transaction to send 1 ETH to Bob from Alice.

~~~cs
// Define amount to send and nonce
let amount = etherToWei (bigint 1)
let nonce = getTransactionCount (getKey "alice" |> getAddress)
 
let message =
    createTransaction (getAddress bobKey) amount nonce
    |> transactionToMessage
~~~
This will create a byte array of the data passed, setting some default values for gas price and gas limit. The next step is preparing the data for signing. This is done by RLP encoding the message and hashing it using Keccak 256. We can use the same function we used in part 1 to compute the hash.

~~~cs
// Compute the hash of the message
let rawHash =
    encodeRlp message None
    |> computeHash (KeccakDigest 256)
~~~

### Signing the message
The process of signing the message is done in few steps. The final result will be contain R, S and V values. The R and S represent the signed message array, while V is the recovery id. The recovery is used to recover the original public key that was used to sign the message. Without the recovery id, the algorithm can only determine 4 public keys that are candidates and produce the same signed data. The recovery id helps us identify which one was actually used with the transaction.

~~~cs
let findRecoveryId signature message publicKey =
    let isMatch i =
        let recovered = ECKey.RecoverFromSignature(i, signature, message, false)
        recovered <> null
        && areEqual (recovered.GetPubKey(false)) publicKey
 
    [0 .. 3]
    |> List.tryFind isMatch
    |> fun x -> defaultArg x -1
~~~
The above code does brute force check using the recovery algorithm. Whenever a key is recovered that matches the original public key, we set that recovery id as V parameter of the signature.

To sign the message with Key Vault, we add the function to our wrapper

~~~cs
let signKey keyId digest =
    async {
        let! result = client.SignAsync(keyId, "ECDSA256", digest)
        return result
    } |> Async.RunSynchronously
~~~
The output of this will be a 64 byte array. The first 32 are the value for R and the rest is S. We then append the value for V and return the entire signature object.

~~~cs
let signMessage (keyBundle:KeyBundle) message =
    // Construct public key and append 0x04
    let pubKey = Array.concat [| [| byte 4|]; keyBundle.Key.X; keyBundle.Key.Y |]
    let keyId = keyBundle.KeyIdentifier.Identifier
 
    // Compute the hash of the message
    let rawHash =
        encodeRlp message None
        |> computeHash (KeccakDigest 256)
 
    // Sign the hash with key vault and return ECDSASignature
    let signature =
        let result = signKey keyId rawHash
 
        let R = Array.take 32 result.Result
        let S = Array.skip 32 result.Result
 
        [| BigInt(1, R)
           BigInt(1, S) |]
        |> ECDSASignature
        |> fun x -> x.MakeCanonical()
 
    // Find the recovery id
    let recId = findRecoveryId signature rawHash pubKey
 
    // We must throw here, something went wrong
    if recId = -1 then failwith "Invalid signature"
 
    signature.V <- byte (recId + 27)
    Some signature
~~~

### Serialize everything to get the final transaction data
Once we have everything nicely signed and formatted we’re ready to obtain the final raw data of the offline transaction. Let’s run everything in order
~~~cs
// Construct the full offline transaction hash
let txHash =
    message
    |> signMessage aliceKey
    |> encodeRlp message
    |> toHex
    |> (+) "0x"
~~~
This will produce a hex string representing a transaction. We can commit this data inside geth using `eth.sendRawTransaction("txHash")` or use the RPC client wrapper function
~~~cs
sendRawTransaction txHash
|> printfn "Transaction %s sent"
~~~
Once this is done, run `miner.start()` inside your geth console to start mining the transactions. Bob should get 1 ETH on his address. Check with `eth.getBalance("bob's address")`

Thank you for reading this. Feel free to reach out if you have any questions or leave a comment.

[Full Source Code](https://github.com/tmarkovski/ethereum-key-vault){: .btn .btn-success .btn-lg}