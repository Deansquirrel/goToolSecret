package goToolSecret

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"strings"
)

var key []byte

func init() {
	key = []byte("Deansquirrel521247944341")
}

func SetCode(code string) {
	code = strings.Trim(code, " ")
	if code == "" {
		key = nil
	} else {
		key = []byte(code)
	}
}

//加密内容作Base64编码
func EncryptStr(str string) (string, error) {
	b, err := Encrypt([]byte(str))
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(b), nil
}

//解密Base64编码
func DecryptStr(str string) (string, error) {
	b, err := base64.StdEncoding.DecodeString(str)
	if err != nil {
		return "", err
	}
	r, err := Decrypt(b)
	if err != nil {
		return "", err
	}
	return string(r), nil
}

//加密
func Encrypt(str []byte) ([]byte, error) {
	if key == nil {
		return str, nil
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	blockSize := block.BlockSize()
	str = PKCS7Padding(str, blockSize)
	blockModel := cipher.NewCBCEncrypter(block, key[:blockSize])
	result := make([]byte, len(str))
	blockModel.CryptBlocks(result, str)
	return result, nil
}

//解密
func Decrypt(str []byte) ([]byte, error) {
	if key == nil {
		return str, nil
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	blockSize := block.BlockSize()
	blockModel := cipher.NewCBCDecrypter(block, key[:blockSize])
	result := make([]byte, len(str))
	blockModel.CryptBlocks(result, str)
	result = PKCS7UnPadding(result)
	return result, nil
}

func PKCS7Padding(cipherText []byte, blockSize int) []byte {
	padding := blockSize - len(cipherText)%blockSize
	padText := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(cipherText, padText...)
}

func PKCS7UnPadding(origData []byte) []byte {
	length := len(origData)
	unPadding := int(origData[length-1])
	return origData[:(length - unPadding)]
}
