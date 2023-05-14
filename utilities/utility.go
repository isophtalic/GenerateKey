package utilities

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"math/rand"
	"os"
)

func LoadKeyFromFile(publicKeyPath, privateKeyPath string) (*rsa.PublicKey, *rsa.PrivateKey) {
	pubKey, priKey := loadPublicKeyFromFile(publicKeyPath), loadRSAPrivateKeyFromFile(privateKeyPath)
	return pubKey.(*rsa.PublicKey), priKey.(*rsa.PrivateKey)
}

func loadPublicKeyFromFile(publicKeyPath string) interface{} {
	publicKeyFile, err := os.ReadFile(publicKeyPath)
	if err != nil {
		panic(err)
	}
	return PemStringToRSAPublicKey(publicKeyFile)
}

func loadRSAPrivateKeyFromFile(privateKeyPath string) interface{} {
	privateKeyFile, err := os.ReadFile(privateKeyPath)
	if err != nil {
		panic(err)
	}
	return PEMStringToRSAPrivateKey(privateKeyFile)
}

func PemStringToRSAPublicKey(pemString []byte) interface{} {
	publicKeyBlock, _ := pem.Decode(pemString)
	if publicKeyBlock == nil {
		panic("failed to parse PEM block containing the public key")
	}
	publicKey, err := x509.ParsePKCS1PublicKey(publicKeyBlock.Bytes)
	if err != nil {
		panic(err)
	}

	return publicKey
}

func PEMStringToRSAPrivateKey(pemString []byte) interface{} {
	privateKeyBlock, _ := pem.Decode(pemString)
	privateKey, err := x509.ParsePKCS1PrivateKey(privateKeyBlock.Bytes)
	if err != nil {
		panic(err)
	}

	return privateKey
}

func KeyGenerateString() (key string) {
	for i := 0; i < 5; i++ {
		link := ""
		if i != 4 {
			link = "-"
		}
		key += randStringRunes(5) + link
	}
	return
}

func randStringRunes(n int) string {
	var letters = []rune("0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ")
	b := make([]rune, n)
	for i := range b {
		b[i] = letters[rand.Intn(len(letters))]
	}
	return string(b)
}
