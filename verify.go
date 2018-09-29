package lcns

import (
	"bytes"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/gob"
	"errors"
	"strings"
)

// VerifyAndExtractPayload takes a rsa.PublicKey and a license key string
// generated with GenerateFromPayload to return an empty interface holding the
// included payload. A nil interface and an error is returned if the license key
// is invalid or corrupt. You are expected to assert and convert it to your
// type; remember that this may cause a panic if you convert to a concrete
// different type than the one you generated the license key with.
func VerifyAndExtractPayload(publicKey *rsa.PublicKey, str string) (interface{}, error) {
	var err error

	str = strings.TrimSpace(str)

	if !strings.HasPrefix(str, header) || !strings.HasSuffix(str, footer) {
		return nil, errors.New("invalid license key")
	}

	b64 := strings.Replace(str[len(header):len(str)-len(footer)], "\n", "", -1)

	var l license
	b, err := base64.StdEncoding.DecodeString(b64)
	licenseBuffer := bytes.Buffer{}
	licenseBuffer.Write(b)
	licenseDecoder := gob.NewDecoder(&licenseBuffer)
	if err = licenseDecoder.Decode(&l); err != nil {
		return nil, err
	}

	hashed := sha256.Sum256(l.Payload)

	if err = rsa.VerifyPKCS1v15(publicKey, crypto.SHA256, hashed[:], l.Signature); err != nil {
		return nil, err
	}

	var payload interface{}
	payloadBuffer := bytes.Buffer{}
	payloadBuffer.Write(l.Payload)
	payloadDecoder := gob.NewDecoder(&payloadBuffer)
	if err = payloadDecoder.Decode(&payload); err != nil {
		return nil, err
	}

	return payload, nil
}
