package lcns

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
)

// ReadPrivateKey reads a PEM-encoded X.509 RSA private key and returns a
// rsa.PrivateKey that can be used in GenerateFromPayload to generate a license
// key from a payload.
func ReadPrivateKey(filename string) (*rsa.PrivateKey, error) {
	contents, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(contents)
	if block == nil {
		return nil, errors.New(fmt.Sprintf("no PEM encoded key found in %s", filename))
	}

	if block.Type != "RSA PRIVATE KEY" {
		return nil, errors.New(fmt.Sprintf("unknown PEM block type %s", block.Type))
	}

	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	return privateKey, err
}

// ReadPublicKey reads a PEM-encoded X.509 RSA public key and returns a
// rsa.PublicKey that can be used in VerifyAndExtractPayload to verify a license
// key and extract the included payload.
func ReadPublicKey(filename string) (*rsa.PublicKey, error) {
	contents, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(contents)
	if block == nil {
		return nil, errors.New(fmt.Sprintf("no PEM encoded key found in %s", filename))
	}

	if block.Type != "PUBLIC KEY" {
		return nil, errors.New(fmt.Sprintf("unknown PEM block type %s", block.Type))
	}

	publicKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	return publicKey.(*rsa.PublicKey), nil
}
