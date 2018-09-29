package lcns

type license struct {
	Payload   []byte
	Signature []byte
}

var header string = "-----BEGIN LICENSE KEY-----"
var footer string = "-----END LICENSE KEY-----"
