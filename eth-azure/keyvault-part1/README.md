# Securing Ethereum keys with Azure Key Vault

by Tomislav Markovski

```fsharp
let getAddress pubKey =
    pubKey
    |> computeHash (new KeccakDigest(256))
    |> Array.map toHex
    |> Array.skip 12
    |> String.Concat
    |> (+) "0x"
```
