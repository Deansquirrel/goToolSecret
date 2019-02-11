package goToolSecret

import "strings"

var key string

const (
	KeyAlgorithm           = "AES"
	DefaultCipherAlgorithm = "AES/ECB/PKCS5Padding"
)

func init() {
	key = "Deansquirrel521247944341"
}

func SetCode(code string) {
	key = strings.Trim(code, " ")
}

//加密
func Encrypt(str string) (string, error) {
	if key == "" {
		return str, nil
	}

	return "", nil
}

//解密
func Decrypt(str string) (string, error) {
	if key == "" {
		return str, nil
	}
	return "", nil
}
