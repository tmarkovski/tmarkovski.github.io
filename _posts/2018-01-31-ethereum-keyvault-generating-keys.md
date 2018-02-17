---
layout: post
title: Ethereum and Azure Key Vault - Part 1
subtitle: Generating keys and deriving address
---
>
This is a multi part article showcasing interaction with Ethereum blockchain using keys secured in Azure Key Vault. I wasn’t able to find any articles on this, most resources available use the web3 tools to generate keys, so I decided to share my findings using .NET and Azure.
>
Part 2 of this series is available at [Ethereum and Azure Key Vault. Part 2 – Signing offline transactions](/2018-02-05-ethereum-keyvault-signing-transactions)

---
## Part 1: Generating keys and ethereum address

- Setup access to Key Vault
- Derive Ethereum address
- Running the sample

In this part I’ll show how to create EC keys and generate Ethereum address from the public key using Azure Key Vault. Last year, Microsoft added support to Key Vault for elliptic curve keys including secp256k1 curve. Important thing to note is that this curve is only available for Key Vault under Premium SKU, not Standard.

The sample code uses Bouncy Castle and Azure Key Vault preview package for .NET. Code is in F#, but it’s easy to understand and recode to your flavor.

Full project source code is [available here](https://github.com/tmarkovski/ethereum-key-vault).

### Setup access to Key Vault
The code assumes that Key Vault is configured with a service principal access, but this can adjusted to fit any authentication scenario.

```cs
let vaultUri = "..."
let clientId = "..."
let clientSecret "..."
 
let getAccessToken (authority:string) (resource:string) (scope:string) =
    let clientCredential = new ClientCredential(clientId, clientSecret)
    let context = new AuthenticationContext(authority, TokenCache.DefaultShared)
        async {
            let! result = context.AcquireTokenAsync(resource, clientCredential)
            return result.AccessToken;
        } |> Async.StartAsTask
 
let client =
    AuthenticationCallback getAccessToken
    |> KeyVaultCredential
    |> KeyVaultClient
```

Let’s add couple of functions for creating and retrieving keys

~~~cs
let createKey name keyParams =
    async {
        let! result = client.CreateKeyAsync(vaultUri, name, parameters = keyParams)
        return result
    } |> Async.RunSynchronously
 
let getKey name =
    async {
        let! result = client.GetKeyAsync(vaultUri, keyName = name)
        return result
    } |> Async.RunSynchronously
~~~

Create some key parameters to pass to the createKey function

~~~cs
let newKeyParams =
    new NewKeyParameters(
        Kty = "EC-HSM",
        CurveName = "SECP256K1",
        KeyOps = toList [ "sign"; "verify" ])
~~~
We won’t need any other operations other than sign and verify, but this can be edited later or through the Azure Portal.

Create a key for Alice

~~~cs
newKeyParams
|> createKey "alice"
~~~
Running this in the F# interactive will return repsonse similar to this
~~~
val it : KeyBundle =
Microsoft.Azure.KeyVault.Models.KeyBundle
{Attributes = Microsoft.Azure.KeyVault.Models.KeyAttributes;
    Key = {"kid":"https://...vault.azure.net/keys/alice/73dcd8f08e704827873c0ca8519f4d0b",
    "kty":"EC-HSM",
    "key_ops":["sign","verify"],
    "crv":"SECP256K1",
    "x":"ByCZWTlLs3X...",
    "y":"eS0pFg2ALi2VDkw...."};
KeyIdentifier = https://...vault.azure.net:443/keys/alice/73dcd8f08e704827873c0ca8519f4d0b;
Managed = null;
Tags = null;}
~~~
Notice that the repsonse contains the public key in JSON Web Key format. For elliptic curve, the values X and Y represent the points on the curve. Value D represents the private key in JWK format, but D is never returned. We will need the public key to derive the Ethereum address and later to find the recovery id during the process of signing.

### Derive Ethereum address
In order to obtain the Ethereum address, we need to restore the full public key first. This is done simply by concatenating the X and Y arrays. Note that elliptic curve keys may be prefixed with 0x04 as the starting byte making the key 65 bytes long. This is not needed in our case.

~~~cs
let getPubKey (bundle:KeyBundle) : Buffer =
    Array.concat [| bundle.Key.X; bundle.Key.Y |]
~~~
The buffer is then hashed using Keccak-256 function. We can use Bouncy Castle’s implementation for this step.

```cs
let computeHash (digest:IDigest) (data:Buffer) : Buffer =
    let result = digest.GetDigestSize() |> Array.zeroCreate
    digest.BlockUpdate(data, 0, data.Length)
    digest.DoFinal(result, 0) |> ignore
    result
```
The output of Keccak is 64 byte hash (32 hex characters). The address is obtained by taking the last 40 bytes (20 hex chars) and prefixing it with 0x for a total of 42 bytes. Here are the full details of the EIP-150 spec for Ethereum.

To obtain the address we need

~~~cs
let getAddress (pubKey:Buffer) : string =
     pubKey
     |> computeHash (KeccakDigest 256)
     |> Array.map toHex
     |> Array.skip 12
     |> String.Concat
     |> (+) "0x"
~~~

### Running the sample
We’re finally ready to run some code.
Create a key for Bob

~~~csharp
newKeyParams
|> createKey "bob"
~~~
Retrive the key and print the address
~~~csharp
getKey "bob"
|> getPubKey
|> getAddress
|> printfn "Address: %s"
~~~
 
`// 0xd2b70621c23ad7c65be579999021dd87b16fe522`

That’s it! Bob is now ready to talk to the blockchain.

---
Check out the [entire source code](https://github.com/tmarkovski/ethereum-key-vault). I generated a sample project with `dotnet new console -lang f#` and just played with a script file and F# interactive.

Feel free to reach out with any questions or issues.

If you liked this article, please check out [part 2 on signing offline transactions](/2018-02-05-ethereum-keyvault-signing-transactions).