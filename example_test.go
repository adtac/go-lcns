package lcns

import (
	"encoding/gob"
	"testing"
)

func TestExample(t *testing.T) {
	Example(t)
}

func Example(t *testing.T) {
	// Read the public and private keys from disk. In practice, you'd be doing only
	// one of these; the server would read the private key and the client would
	// read the public key.
	publicKey, err := ReadPublicKey("testfiles/publickey.crt")
	if err != nil {
		t.Errorf("error reading public key: %v", err)
		return
	}

	privateKey, err := ReadPrivateKey("testfiles/keypair.pem")
	if err != nil {
		t.Errorf("error reading private key: %v", err)
		return
	}

	// First let's generate licenses with payloads of built-in types (such as int,
	// string). Usually, these payloads contain some identifying information about the
	// client. You'll be doing the license key generation on the server side, of course.
	licenseKeyString, err := GenerateFromPayload(privateKey, "some payload")
	if err != nil {
		t.Errorf("error generating license key: %v", err)
		return
	}

	// Now on the client side, let's verify the license by making sure the signature
	// matches and extract the payload. You'll be doing this on the client side.
	payload, err := VerifyAndExtractPayload(publicKey, licenseKeyString)
	if err != nil {
		t.Errorf("error verifying license: %v", err)
		return
	}

	// Make sure the payload matches.
	if payload != "some payload" {
		t.Errorf("expected payload to be 'some payload' got '%s' instead", payload)
		return
	}

	// Using custom structs as payloads is possible, too, but you need to first
	// register the struct. Remember to export all the fields!
	type foo struct {
		Bar string
		Baz int
	}
	x := foo{"bar", 100}

	// To register a struct, call gob.Register from the encoding/gob package like so.
	gob.Register(foo{})
	licenseKeyString, err = GenerateFromPayload(privateKey, x)
	if err != nil {
		t.Errorf("error generating license key: %v", err)
		return
	}

	// Since the license verification part will be running on the client-side, you'll
	// need to register the struct before verification like so.
	gob.Register(foo{})
	payload, err = VerifyAndExtractPayload(publicKey, licenseKeyString)
	if err != nil {
		// The license key was probably invalid or corrupt.
		t.Errorf("error verifying license: %v", err)
		return
	}

	// To convert the empty interface into your type, cast it. Remember, this may
	// cause panics if the type you're not converting to the original type. Let's make
	// sure the payload matches.
	if payload.(foo) != x {
		t.Errorf("expected payload to be %v got %v instead", x, payload)
		return
	}
}
