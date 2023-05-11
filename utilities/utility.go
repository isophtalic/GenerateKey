package utilities

import (
	"crypto/dsa"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
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
	return pemStringToPublicKey(publicKeyFile)
}

func loadRSAPrivateKeyFromFile(privateKeyPath string) interface{} {
	privateKeyFile, err := os.ReadFile(privateKeyPath)
	if err != nil {
		panic(err)
	}
	privateKeyBlock, _ := pem.Decode(privateKeyFile)
	privateKey, err := x509.ParsePKCS1PrivateKey(privateKeyBlock.Bytes)
	if err != nil {
		panic(err)
	}

	return privateKey
}

func pemStringToPublicKey(pemString []byte) interface{} {
	publicKeyBlock, _ := pem.Decode(pemString)
	if publicKeyBlock == nil {
		panic("failed to parse PEM block containing the public key")
	}
	publicKey, err := x509.ParsePKIXPublicKey(publicKeyBlock.Bytes)
	if err != nil {
		panic(err)
	}
	var key interface{}

	switch pub := publicKey.(type) {
	case *rsa.PublicKey:
		key = (*rsa.PublicKey)(pub)
	case *dsa.PublicKey:
		key = (*dsa.PublicKey)(pub)
	case *ecdsa.PublicKey:
		key = (*ecdsa.PublicKey)(pub)
	default:
		panic("unknown type of public key")
	}
	return key
}
