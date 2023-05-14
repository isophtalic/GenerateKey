package rsa

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"hash"
	"io"
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
		Type:  "RSA PUBLIC KEY",
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
	cipherText, err := encryptOAEP(sha256.New(), rand.Reader, publicKey, []byte(dataInfo), nil)
	if err != nil {
		log.Fatal(err)
	}
	cipherEncoded = base64.StdEncoding.EncodeToString(cipherText)
	return
}

func (*RSA) Decrypt(cipherText []byte, privateKey *rsa.PrivateKey) (plainText []byte) {
	plainText, err := decryptOAEP(sha256.New(), rand.Reader, privateKey, cipherText, nil)
	if err != nil {
		log.Fatal(err)
	}
	return
}

func encryptOAEP(hash hash.Hash, random io.Reader, public *rsa.PublicKey, msg []byte, label []byte) ([]byte, error) {
	msgLen := len(msg)
	step := public.Size() - 2*hash.Size() - 2
	var encryptedBytes []byte

	for start := 0; start < msgLen; start += step {
		finish := start + step
		if finish > msgLen {
			finish = msgLen
		}

		encryptedBlockBytes, err := rsa.EncryptOAEP(hash, random, public, msg[start:finish], label)
		if err != nil {
			return nil, err
		}

		encryptedBytes = append(encryptedBytes, encryptedBlockBytes...)
	}

	return encryptedBytes, nil
}

func decryptOAEP(hash hash.Hash, random io.Reader, private *rsa.PrivateKey, msg []byte, label []byte) ([]byte, error) {
	msgLen := len(msg)
	step := private.PublicKey.Size()
	var decryptedBytes []byte

	for start := 0; start < msgLen; start += step {
		finish := start + step
		if finish > msgLen {
			finish = msgLen
		}

		decryptedBlockBytes, err := rsa.DecryptOAEP(hash, random, private, msg[start:finish], label)
		if err != nil {
			return nil, err
		}

		decryptedBytes = append(decryptedBytes, decryptedBlockBytes...)
	}

	return decryptedBytes, nil
}
