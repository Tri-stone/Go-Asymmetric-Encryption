package pripub

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"os"
)

//GenRsaKey RSA公钥私钥产生
func GenRsaKey(bits int) error {
	// 生成私钥文件
	privateKey, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return err
	}
	derStream := x509.MarshalPKCS1PrivateKey(privateKey)
	block := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: derStream,
	}
	file, err := os.Create("private.pem")
	if err != nil {
		return err
	}
	err = pem.Encode(file, block)
	if err != nil {
		return err
	}
	// 生成公钥文件
	publicKey := &privateKey.PublicKey
	derPkix, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return err
	}
	block = &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: derPkix,
	}
	file, err = os.Create("public.pem")
	if err != nil {
		return err
	}
	err = pem.Encode(file, block)
	if err != nil {
		return err
	}
	return nil
}

// //RsaSignWithShaHex 签名
// func RsaSignWithShaHex(data string, prvKey []byte) (string, error) {
// 	//获取私钥
// 	block, _ := pem.Decode(prvKey)
// 	if block == nil {
// 		return "", errors.New("private key error")
// 	}

// 	// keyByts, err := hex.DecodeString(prvKey)
// 	// if err != nil {
// 	// 	fmt.Println(err)
// 	// 	return "", err
// 	// }
// 	privateKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
// 	if err != nil {
// 		fmt.Println("ParsePKCS8PrivateKey err", err)
// 		return "", err
// 	}
// 	h := sha1.New()
// 	h.Write([]byte([]byte(data)))
// 	hash := h.Sum(nil)
// 	signature, err := rsa.SignPKCS1v15(rand.Reader, privateKey.(*rsa.PrivateKey), crypto.SHA1, hash[:])
// 	if err != nil {
// 		fmt.Printf("Error from signing: %s\n", err)
// 		return "", err
// 	}
// 	out := hex.EncodeToString(signature)
// 	return out, nil
// }

// //RsaVerifySignWithShaBase64 验签
// func RsaVerifySignWithShaBase64(originalData string, signData string, pubKey string) error {
// 	sign, err := base64.StdEncoding.DecodeString(signData)
// 	if err != nil {
// 		return err
// 	}
// 	public, _ := base64.StdEncoding.DecodeString(pubKey)
// 	pub, err := x509.ParsePKIXPublicKey(public)
// 	if err != nil {
// 		return err
// 	}
// 	hash := sha1.New()
// 	hash.Write([]byte(originalData))
// 	return rsa.VerifyPKCS1v15(pub.(*rsa.PublicKey), crypto.SHA1, hash.Sum(nil), sign)
// }

// RsaSign 私钥签名
func RsaSign(data []byte, privateKey []byte) ([]byte, error) {
	h := sha256.New()
	h.Write(data)
	hashed := h.Sum(nil)
	//获取私钥
	block, _ := pem.Decode(privateKey)
	if block == nil {
		return nil, errors.New("private key error")
	}
	//解析PKCS1格式的私钥
	priv, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	return rsa.SignPKCS1v15(rand.Reader, priv, crypto.SHA256, hashed)
}

// RsaSignVer 公钥验证
func RsaSignVer(data []byte, signature []byte, publicKey []byte) error {
	hashed := sha256.Sum256(data)
	block, _ := pem.Decode(publicKey)
	if block == nil {
		return errors.New("public key error")
	}
	// 解析公钥
	pubInterface, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return err
	}
	// 类型断言
	pub := pubInterface.(*rsa.PublicKey)
	//验证签名
	return rsa.VerifyPKCS1v15(pub, crypto.SHA256, hashed[:], signature)
}

// RsaEncrypt 公钥加密
func RsaEncrypt(data []byte, publicKey []byte) ([]byte, error) {
	//解密pem格式的公钥
	block, _ := pem.Decode(publicKey)
	if block == nil {
		return nil, errors.New("public key error")
	}
	// 解析公钥
	pubInterface, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	// 类型断言
	pub := pubInterface.(*rsa.PublicKey)
	//加密
	return rsa.EncryptPKCS1v15(rand.Reader, pub, data)
}

// RsaDecrypt 私钥解密
func RsaDecrypt(ciphertext []byte, privateKey []byte) ([]byte, error) {
	//获取私钥
	block, _ := pem.Decode(privateKey)
	if block == nil {
		return nil, errors.New("private key error")
	}
	//解析PKCS1格式的私钥
	priv, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	// 解密
	return rsa.DecryptPKCS1v15(rand.Reader, priv, ciphertext)
}
