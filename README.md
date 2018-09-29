### `go-lcns`

[![GoDoc](https://godoc.org/github.com/adtac/go-lcns/github?status.svg)](https://godoc.org/github.com/adtac/go-lcns)

`go-lcns` is a license generation and verification library for Go that uses RSA cryptography underneath. I use this for the enterprise edition of [**Commento**](https://commento.io).

##### Usage

A code snippet speaks a thousand words. Check out [**godoc**](https://godoc.org/github.com/adtac/go-lcns) for more details.

```go
import "github.com/adtac/go-lcns"
```

```go
// Read the public and private keys from disk. In practice, you'd be doing only
// one of these; the server would read the private key and the client would
// read the public key.
publicKey, err := ReadPublicKey("testfiles/publickey.crt")
privateKey, err := ReadPrivateKey("testfiles/keypair.pem")
```

```go
// First let's generate licenses with payloads of built-in types (such as int,
// string). Usually, these payloads contain some identifying information about the
// client. You'll be doing the license key generation on the server side, of course.
licenseKeyString, err := GenerateFromPayload(privateKey, "some payload")
```

```go
// Now on the client side, let's verify the license by making sure the signature
// matches and extract the payload. You'll be doing this on the client side.
payload, err := VerifyAndExtractPayload(publicKey, licenseKeyString)
if err != nil {
  // The license was probably invalid or corrupt.
}

fmt.Println(payload)  // "some payload"
```

Using custom structs as payloads is possible, too, but you need to first register the struct. Remember to export all the fields!


```go
type foo struct {
  Bar string
  Baz int
}
x := foo{"bar", 100}
```

```go
// On the server side, you generate the license key.
gob.Register(foo{})
licenseKeyString, err = GenerateFromPayload(privateKey, x)
```

```go
// On the client side, you verify the license key. Make sure to use the same struct;
// you may get panics, errors, and other monsters otherwise.
gob.Register(foo{})
payload, err = VerifyAndExtractPayload(publicKey, licenseKeyString)
if err != nil {
  // The license was probably invalid or corrupt.
}

// You can cast the empty interface returned by VerifyAndExtractPayload like so.
fooObject := payload.(foo)
```
