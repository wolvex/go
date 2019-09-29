package encryption

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"net/url"
)

func TykHmacSign(input, secret string) string {
	// SHA1 Encode the signature
	h := hmac.New(sha256.New, []byte(secret))
	h.Write([]byte(input))

	// Base64 and URL Encode the string
	sigString := base64.StdEncoding.EncodeToString(h.Sum(nil))
	encodedString := url.QueryEscape(sigString)

	return encodedString
}
