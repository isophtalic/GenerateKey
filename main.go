package main

import (
	"fmt"
	"math/rand"
)

func main() {
	fmt.Println(KeyGenerateString())
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
