package encryption

import (
	"encoding/hex"
	"math/rand"
	"time"
)

func RandomHex(n int) string {
	bytes := make([]byte, n)
	rand.Seed(time.Now().UnixNano())
	if _, err := rand.Read(bytes); err != nil {
		return "0"
	}
	return hex.EncodeToString(bytes)
}
