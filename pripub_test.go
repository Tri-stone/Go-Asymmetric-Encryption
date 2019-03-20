package pripub

import (
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"testing"
)

func TestGenRsaKey(t *testing.T) {
	GenRsaKey(1024)
}

func TestRsaSignWithShaHex(t *testing.T) {
	data := "7b2261646472657373223a22227d"
	privateKey, err := ioutil.ReadFile("private.pem")

	dataByte, _ := hex.DecodeString(data)

	result, err := RsaSign(dataByte, privateKey)

	if err != nil {
		fmt.Println("error:", err)
	} else {
		fmt.Println(result)
		resultHex := hex.EncodeToString(result)
		fmt.Println((resultHex))
		resultByte, _ := hex.DecodeString(resultHex)
		fmt.Println(resultByte)
	}
}

func TestRsaVerifySignWithShaBase64(t *testing.T) {
	originalData := "7b2261646472657373223a22227d"

	pubkey, err := ioutil.ReadFile("public.pem")

	privateKey, err := ioutil.ReadFile("private.pem")

	originalDataByte, _ := hex.DecodeString(originalData)

	result, err := RsaSign(originalDataByte, privateKey)

	signData := result

	err = RsaSignVer(originalDataByte, signData, pubkey)

	if err != nil {
		fmt.Println("error")
	} else {
		fmt.Println("success")
	}
}

func TestRsaVerify2SignWithShaBase64(t *testing.T) {
	originalData := "7b2261646472657373223a22227d"

	pubkey, err := ioutil.ReadFile("public.pem")

	originalDataByte, _ := hex.DecodeString(originalData)

	signData := "89dae7a58952bb013ba771025af2680450e445663974bd7dd48f066b1d46a2a3975772962253bdf4c78c03867926546d31d3e487c26260cef0d5aecc13f156be7f7a7d8dc6447fc29972fea1a7a4a828673625c3d460c08ff4c385a0d10fc4430714b50afefe3126306f32380e87027a9bc0a926bec68a64d7b7a603236523e7"

	signDataByte, _ := hex.DecodeString(signData)

	err = RsaSignVer(originalDataByte, signDataByte, pubkey)

	if err != nil {
		fmt.Println("error")
	} else {
		fmt.Println("success")
	}
}
