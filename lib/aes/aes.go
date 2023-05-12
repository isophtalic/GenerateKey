package aes

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"reflect"
)

type AES struct{}

func (*AES) Encrypt(block cipher.Block, iv []byte, plaintext string) []byte {
	objectBytes := []byte(plaintext)
	mode := cipher.NewCBCEncrypter(block, iv)

	objectBytes = pad(objectBytes, aes.BlockSize)

	cipherText := make([]byte, len(objectBytes))

	mode.CryptBlocks(cipherText, objectBytes)

	return cipherText
}

func (*AES) Decrypt(block cipher.Block, iv []byte, cipherText string) []byte {
	cipherTextBytes, err := base64.StdEncoding.DecodeString(cipherText)
	if err != nil {
		er := fmt.Sprintf("Error decoding ciphertext: %s", err)
		panic(er)
	}

	mode := cipher.NewCBCDecrypter(block, iv)

	plaintext := make([]byte, len(cipherTextBytes))

	mode.CryptBlocks(plaintext, cipherTextBytes)

	plaintext = unPad(plaintext)

	return plaintext
}

// Generate a random 32-byte key for AES-256
func (*AES) GenerateKeyBYTES(numberKeyByte int) []byte {
	var err error
	key := make([]byte, 32)
	_, err = rand.Read(key)
	if err != nil {
		er := fmt.Sprintf("Error generating key: %s", err)
		panic(er)
	}
	return key
}

// Create a new AES cipher block
func (*AES) MakeCipherBlock(key []byte) cipher.Block {
	// Create a new AES cipher block
	block, err := aes.NewCipher(key)
	if err != nil {
		er := fmt.Sprintf("Error creating cipher block: %s", err)
		panic(er)
	}
	return block
}

// Generate a random 16-byte IV (Initialization Vector)
func (*AES) GenerateInitializationVector() []byte {
	iv := make([]byte, aes.BlockSize)
	_, err := rand.Read(iv)
	if err != nil {
		er := fmt.Sprintf("Error generating IV: %s", err)
		panic(er)
	}
	return iv
}

func pad(data []byte, blockSize int) []byte {
	padding := blockSize - (len(data) % blockSize)
	padText := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(data, padText...)
}

func unPad(data []byte) []byte {
	padding := int(data[len(data)-1])
	return data[:len(data)-padding]
}

func structToBytes(object interface{}) []byte {
	value := reflect.ValueOf(object)

	if value.Kind() != reflect.Struct {
		panic("Input is not a struct")
	}

	structBytes := []byte{}

	// Iterate over the struct fields
	for i := 0; i < value.NumField(); i++ {
		fieldValue := value.Field(i)

		// Check if the field value is a string
		if fieldValue.Kind() == reflect.String {
			fieldBytes := []byte(fieldValue.String())
			structBytes = append(structBytes, fieldBytes...)
		}
	}

	return structBytes
}
