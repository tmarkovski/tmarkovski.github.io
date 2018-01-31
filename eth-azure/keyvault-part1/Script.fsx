#r @"C:\Users\Tomislav\.nuget\packages\microsoft.azure.keyvault\2.4.0-preview\lib\netstandard1.4\Microsoft.Azure.KeyVault.dll"
#r @"C:\Users\Tomislav\.nuget\packages\microsoft.azure.keyvault.core\2.0.5-preview\lib\netstandard1.4\Microsoft.Azure.KeyVault.Core.dll"
#r @"C:\Users\Tomislav\.nuget\packages\microsoft.azure.keyvault.cryptography\2.0.6-preview\lib\netstandard1.4\Microsoft.Azure.KeyVault.Cryptography.dll"
#r @"C:\Users\Tomislav\.nuget\packages\microsoft.azure.keyvault.webkey\2.1.0-preview\lib\netstandard1.4\Microsoft.Azure.KeyVault.WebKey.dll"
#r @"C:\Users\Tomislav\.nuget\packages\system.security.cryptography.algorithms\4.3.1\lib\net463\System.Security.Cryptography.Algorithms.dll"
#r @"C:\Users\Tomislav\.nuget\packages\system.security.cryptography.cng\4.4.0\lib\net47\System.Security.Cryptography.Cng.dll"
#r @"C:\Users\Tomislav\.nuget\packages\microsoft.rest.clientruntime\2.3.10\lib\netstandard1.4\Microsoft.Rest.ClientRuntime.dll"
#r @"C:\Users\Tomislav\.nuget\packages\microsoft.rest.clientruntime.azure\3.3.10\lib\netstandard1.4\Microsoft.Rest.ClientRuntime.Azure.dll"
#r @"C:\Users\Tomislav\.nuget\packages\microsoft.identitymodel.clients.activedirectory\3.17.3\lib\netstandard1.3\Microsoft.IdentityModel.Clients.ActiveDirectory.dll"
#r @"C:\Users\Tomislav\.nuget\packages\system.net.http\4.3.3\lib\net46\System.Net.Http.dll"
#r @"C:\Users\Tomislav\.nuget\packages\portable.bouncycastle\1.8.1.3\lib\netstandard1.3\BouncyCastle.Crypto.dll"

open System
open System.Threading.Tasks
open System.Collections.Generic
open Microsoft.Azure.KeyVault
open Microsoft.IdentityModel.Clients.ActiveDirectory
open Microsoft.Azure.KeyVault.Models
open Microsoft.Azure.KeyVault.WebKey
open Org.BouncyCastle.Crypto.Digests
open Org.BouncyCastle.Crypto

/// Implements an extension method that overloads the standard
/// 'Bind' of the 'async' builder. The new overload awaits on 
/// a standard .NET task
type AsyncBuilder with
  member __.Bind(t:Task<'T>, f:'T -> Async<'R>) : Async<'R>  = 
    async.Bind(Async.AwaitTask t, f)

let toList<'a> (collection:'a list) = new List<'a>(collection)

let toHex (x:byte) = x.ToString("x2")

let vaultUri = "..."
let clientId = "..."
let clientSecret = "..."

type AuthenticationCallback = KeyVaultClient.AuthenticationCallback
type Buffer = byte array

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

let getPubKey (bundle:KeyBundle) : Buffer = 
     Array.concat [| bundle.Key.X; bundle.Key.Y |]

let computeHash (digest:IDigest) (data:Buffer) : Buffer =
    let result = digest.GetDigestSize() |> Array.zeroCreate
    digest.BlockUpdate(data, 0, data.Length)
    digest.DoFinal(result, 0) |> ignore
    result

let getAddress (pubKey:Buffer) : string =
    pubKey
    |> computeHash (KeccakDigest 256)
    |> Array.map toHex
    |> Array.skip 12
    |> String.Concat
    |> (+) "0x"

let hexToBuffer (value:string) : Buffer =
    [| 0 .. value.Length - 1 |]
    |> Array.where (fun x -> x % 2 = 0)
    |> Array.map (fun x -> value.Substring(x, 2))
    |> Array.map (fun x -> Convert.ToByte(x, 16))
    
let newKeyParams = 
    new NewKeyParameters(
        Kty = "EC-HSM", 
        CurveName = "SECP256K1",
        KeyOps = toList [ "sign"; "verify" ])

newKeyParams
|> createKey "alice"

getKey "alice"
|> getPubKey
|> getAddress
|> printfn "Address: %s"

