package main

import (
	"fmt"

	"github.com/isophtalic/GenerateKey/lib/rsa"
	"github.com/isophtalic/GenerateKey/utilities"
)

const (
	publicPath  = "./keys/public.pem"
	privatePath = "./keys/private.pem"
	bitRSA      = 2048
)

type ModelTest struct {
	Email    string
	Password string
}

var newRSA rsa.RSA

func main() {
	var info = &ModelTest{
		Email:    "isoPhtalic",
		Password: "XuanThang",
	}

	err := newRSA.GenerateKey(publicPath, privatePath, bitRSA)
	if err != nil {
		panic(err)
	}
	publicKey, privateKey := utilities.LoadKeyFromFile(publicPath, privatePath)
	cipherText := newRSA.Encrypt(info, publicKey)
	plainText := newRSA.Decrypt(cipherText, privateKey)

	fmt.Println(string(plainText))
}

//export RSA
var RSA rsa.RSA
