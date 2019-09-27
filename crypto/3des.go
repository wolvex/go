package encryption

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"encoding/base64"
	"encoding/hex"
	"errors"
)

func ZeroPadding(ciphertext []byte, blockSize int) []byte {
	padding := blockSize - len(ciphertext)%blockSize
	padtext := bytes.Repeat([]byte{0}, padding)
	return append(ciphertext, padtext...)
}

func ZeroUnPadding(origData []byte) []byte {
	return bytes.TrimFunc(origData,
		func(r rune) bool {
			return r == rune(0)
		})
}

func PKCS5Padding(ciphertext []byte, blockSize int) []byte {
	padding := blockSize - len(ciphertext)%blockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(ciphertext, padtext...)
}

func PKCS5UnPadding(origData []byte) []byte {
	length := len(origData)
	unpadding := int(origData[length-1])
	if length < unpadding {
		return []byte("unpadding error")
	}
	return origData[:(length - unpadding)]
}

func PKCS7Padding(ciphertext []byte, blockSize int) []byte {
	return PKCS5Padding(ciphertext, blockSize)
}

func PKCS7UnPadding(origData []byte) []byte {
	return PKCS5UnPadding(origData)
}

func tripleDesKey(originalKey []byte) []byte {
	key := originalKey
	i := 0
	for len(key) < 24 {
		key = append(key, originalKey[i])
		if i >= len(originalKey)-1 {
			i = 0
		} else {
			i++
		}
	}
	return key[0:24]
}

func TripleDesEncrypt(origData string, key []byte, paddingFunc func([]byte, int) []byte) (string, error) {
	key = tripleDesKey(key)
	iv := key[0:8]

	block, err := des.NewTripleDESCipher(key)
	if err != nil {
		return "", err
	}
	orig := paddingFunc([]byte(origData), block.BlockSize())
	blockMode := cipher.NewCBCEncrypter(block, iv)
	crypted := make([]byte, len(orig))
	blockMode.CryptBlocks(crypted, orig)
	//return strings.ToUpper(hex.EncodeToString(crypted)), nil
	return base64.StdEncoding.EncodeToString(crypted), nil
}

func TripleDesDecrypt(encrypted string, key []byte, unPaddingFunc func([]byte) []byte) (string, error) {
	key = tripleDesKey(key)
	iv := key[0:8]

	//e, err := hex.DecodeString(strings.ToLower(encrypted))
	e, err := base64.StdEncoding.DecodeString(encrypted)
	if err != nil {
		return "", err
	}
	block, err := des.NewTripleDESCipher(key)
	if err != nil {
		return "", err
	}
	blockMode := cipher.NewCBCDecrypter(block, iv)
	origData := make([]byte, len(e))
	blockMode.CryptBlocks(origData, e)
	origData = unPaddingFunc(origData)
	if string(origData) == "unpadding error" {
		return "", errors.New("unpadding error")
	}
	return string(origData), nil
}

func DesEncrypt(src, key string, paddingFunc func([]byte, int) []byte) (string, error) {
	block, err := des.NewCipher([]byte(key))
	if err != nil {
		return "", err
	}
	bs := block.BlockSize()
	src = string(paddingFunc([]byte(src), bs))
	if len(src)%bs != 0 {
		return "", errors.New("Need a multiple of the blocksize")
	}
	out := make([]byte, len(src))
	dst := out
	for len(src) > 0 {
		block.Encrypt(dst, []byte(src)[:bs])
		src = src[bs:]
		dst = dst[bs:]
	}
	return hex.EncodeToString(out), nil
}

func DesDecrypt(src, key string, unPaddingFunc func([]byte) []byte) (string, error) {
	b, _ := hex.DecodeString(src)
	src = string(b)
	block, err := des.NewCipher([]byte(key))
	if err != nil {
		return "", err
	}
	out := make([]byte, len(src))
	dst := out
	bs := block.BlockSize()
	if len(src)%bs != 0 {
		return "", errors.New("crypto/cipher: input not full blocks")
	}
	for len(src) > 0 {
		block.Decrypt(dst, []byte(src)[:bs])
		src = src[bs:]
		dst = dst[bs:]
	}

	out = unPaddingFunc(out)
	return string(out), nil
}

func AesEncrypt(origData, key []byte, iv []byte, paddingFunc func([]byte, int) []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	blockSize := block.BlockSize()
	origData = paddingFunc(origData, blockSize)

	blockMode := cipher.NewCBCEncrypter(block, iv)
	crypted := make([]byte, len(origData))
	blockMode.CryptBlocks(crypted, origData)
	return crypted, nil
}

func AesDecrypt(crypted, key []byte, iv []byte, unPaddingFunc func([]byte) []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	blockMode := cipher.NewCBCDecrypter(block, iv)
	origData := make([]byte, len(crypted))
	blockMode.CryptBlocks(origData, crypted)
	origData = unPaddingFunc(origData)
	return origData, nil
}
