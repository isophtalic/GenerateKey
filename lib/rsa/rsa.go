package rsa

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"log"
	"os"
)

type RSA struct{}

func (*RSA) GenerateKey(pubKeyPath, privateKeyPath string, bit int) error {
	privateKey, err := rsa.GenerateKey(rand.Reader, bit)
	if err != nil {
		return err
	}

	publicKey := &privateKey.PublicKey

	//save privateKey into file
	privateKeyPem := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	}
	privateKeyFile, err := os.Create(privateKeyPath)
	if err != nil {
		return err
	}
	defer privateKeyFile.Close()
	err = pem.Encode(privateKeyFile, privateKeyPem)
	if err != nil {
		return err
	}

	//save privateKey into file
	publicKeyBytes, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return err
	}
	publicKeyPem := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: publicKeyBytes,
	}
	publicKeyFile, err := os.Create(pubKeyPath)
	if err != nil {
		return err
	}
	defer publicKeyFile.Close()
	err = pem.Encode(publicKeyFile, publicKeyPem)
	if err != nil {
		return err
	}
	fmt.Println("Generate successfully")
	return nil
}

func (*RSA) Encrypt(info interface{}, publicKey *rsa.PublicKey) (cipherText []byte, cipherEncoded string) {
	dataInfo := fmt.Sprintf("%v", info)
	cipherText, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, publicKey, []byte(dataInfo), nil)
	if err != nil {
		log.Fatal(err)
	}
	cipherEncoded = base64.StdEncoding.EncodeToString(cipherText)
	return
}

func (*RSA) Decrypt(cipherText []byte, privateKey *rsa.PrivateKey) (plainText []byte) {
	plainText, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, privateKey, cipherText, nil)
	if err != nil {
		log.Fatal(err)
	}
	return
}
