package goToolSecret

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"github.com/Deansquirrel/goToolCommon"
	"github.com/kataras/iris/core/errors"
)

//将明文加密为Base64格式的密文
//plainText原文
//key密码
func EncryptToBase64Format(plainText string, key string) (string, error) {
	sMD5 := goToolCommon.Md5([]byte(plainText + key))

	var bufferResult bytes.Buffer
	{
		r, err := hex.DecodeString(sMD5)
		if err != nil {
			return "", err
		}
		_, err = bufferResult.Write(r)
		if err != nil {
			return "", err
		}
		_, err = bufferResult.Write([]byte(key))
		if err != nil {
			return "", err
		}
		_, err = bufferResult.Write([]byte(plainText))
		if err != nil {
			return "", err
		}
	}
	resultByte := bufferResult.Bytes()

	keyByte := []byte(key)
	for index := range resultByte {
		resultByte[index] = resultByte[index] ^ (keyByte[index%len(keyByte)])
	}

	var rndKey [4]byte
	for i := 0; i < 4; i++ {
		rndKey[i] = uint8(goToolCommon.RandInt(0, 64))
	}

	for index := range resultByte {
		resultByte[index] = resultByte[index] ^ (rndKey[index%4])
	}

	var bufferFinally bytes.Buffer
	{
		_, err := bufferFinally.Write(rndKey[0:])
		if err != nil {
			return "", err
		}
		_, err = bufferFinally.Write(resultByte)
		if err != nil {
			return "", err
		}
	}

	return base64.StdEncoding.EncodeToString(bufferFinally.Bytes()), nil
}

//将Base64格式的密文解密
//cipherText密文
//key密码
func DecryptFromBase64Format(cipherText string, key string) (string, error) {
	byteCipherText, err := base64.StdEncoding.DecodeString(cipherText)
	if err != nil {
		//base64解码失败
		return "", err
	}

	rndKey := byteCipherText[0:4]

	resultByte := byteCipherText[4:]

	for index := range resultByte {
		resultByte[index] = resultByte[index] ^ (rndKey[index%4])
	}

	keyByte := []byte(key)
	for index := range resultByte {
		resultByte[index] = resultByte[index] ^ (keyByte[index%len(keyByte)])
	}

	checkKeyByte := resultByte[16 : 16+len(keyByte)]

	if !bytes.Equal(keyByte, checkKeyByte) {
		return "", errors.New("解密失败。（密码非法）")
	}

	sMD5Check := resultByte[0:16]
	plainByte := resultByte[16+len(keyByte):]

	var bufferTemp bytes.Buffer
	_, err = bufferTemp.Write(plainByte)
	if err != nil {
		return "", err
	}
	_, err = bufferTemp.Write(keyByte)
	if err != nil {
		return "", err
	}

	sMD5 := goToolCommon.Md5(bufferTemp.Bytes())
	r, err := hex.DecodeString(sMD5)
	if err != nil {
		return "", err
	}

	if !bytes.Equal(sMD5Check, r) {
		return "", errors.New("解密失败。（校验错误）")
	}
	return string(plainByte), nil
}
