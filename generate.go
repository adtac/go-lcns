package lcns

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/gob"
)

// GenerateFromPayload takes a rsa.PrivateKey and a payload to include in the
// license and returns a license key string (if there are no errors). While this works
// without any extra effort for built-in data types (such as int, string), if you
// want to use custom structs as payload, you'll need to register the struct before
// calling GenerateFromPayload with the gob.Register function. See example above.
func GenerateFromPayload(privateKey *rsa.PrivateKey, payload interface{}) (string, error) {
	var err error

	payloadBuffer := bytes.Buffer{}
	payloadEncoder := gob.NewEncoder(&payloadBuffer)
	if err = payloadEncoder.Encode(&payload); err != nil {
		return "", err
	}

	hashed := sha256.Sum256(payloadBuffer.Bytes())
	signature, err := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, hashed[:])

	l := license{
		Payload:   payloadBuffer.Bytes(),
		Signature: signature,
	}

	licenseBuffer := bytes.Buffer{}
	licenseEncoder := gob.NewEncoder(&licenseBuffer)
	if err = licenseEncoder.Encode(l); err != nil {
		return "", err
	}

	b64 := base64.StdEncoding.EncodeToString(licenseBuffer.Bytes())

	result := header + "\n"

	width := 64
	for i := 0; ; i += width {
		if i+width <= len(b64) {
			result += b64[i:i+width] + "\n"
		} else {
			result += b64[i:] + "\n"
			break
		}
	}

	result += footer

	return result, nil
}
