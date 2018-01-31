# Securing Ethereum keys with Azure Key Vault
This is a multi part article showcasing interaction with Ethereum blockchain using keys secured in Azure Key Vault. I wasn't able to find any articles on this, most resources available use the web3 tools to generate keys.
* * *
## Part 1: Generating keys
In this part I'll show how to create EC keys and generate Ethereum address from the public key using Azure Key Vault.
Last year, Microsoft added support to [Key Vault](https://azure.microsoft.com/en-us/pricing/details/key-vault/) for elliptic curve keys including secp256k1 curve. Important thing to note is that this curve is only available for Key Vault under Premium SKU, not Standard.

The sample code uses [Bouncy Castle](https://www.nuget.org/packages/Portable.BouncyCastle/) and [Azure Key Vault](https://www.nuget.org/packages/Microsoft.Azure.KeyVault/2.4.0-preview) preview package for .NET. Code is in F#, but it's easy to understand and recode to your flavor.

Full script source is available here.

### Setup access to Key Vault
The code assumes that Key Vault is configured with a service principal access, but this can adjusted to fit any authentication scenario.

```fsharp
let vaultUri = "https://...vault.azure.net/"
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
Let's add couple of functions for creating and retrieving keys
```fsharp
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
```
Create some key parameters to pass to the `createKey` function
```fsharp
let newKeyParams = 
    new NewKeyParameters(
        Kty = "EC-HSM", 
        CurveName = "SECP256K1",
        KeyOps = toList [ "sign"; "verify" ])
```
We won't need any other operations other than `sign` and `verify`, but this can be edited later or through the Azure Portal.

Create a key for Alice
```fsharp
newKeyParams
|> createKey "alice"
```
Running this in the F# interactive will return repsonse similar to this
```
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
```
Notice that the repsonse contains the public key in [JSON Web Key](https://tools.ietf.org/html/rfc7517) format. For elliptic curve, the values X and Y represent the points on the curve. Value D represents the private key in JWK format, but D is never returned. We will need the the public key to derive the Ethereum address and later to find the recovery id during the process of signing.

### Derive Ethereum address
In order to obtain the Ethereum address, we need to first restore the full public key. This is done by concatenating the X and Y arrays.
```fsharp
let getPubKey (bundle:KeyBundle) : Buffer = 
     Array.concat [| bundle.Key.X; bundle.Key.Y |]
```
The buffer is then hashed using Keccak-256 function. We can use Bouncy Castle's implementation for this step.
```fsharp
let computeHash (digest:IDigest) (data:Buffer) : Buffer =
    let result = digest.GetDigestSize() |> Array.zeroCreate
    digest.BlockUpdate(data, 0, data.Length)
    digest.DoFinal(result, 0) |> ignore
    result
```
