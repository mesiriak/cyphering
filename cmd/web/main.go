package main

import (
	json2 "encoding/json"
	"fmt"
	"github.com/mesiriak/cyphering/pkg/rsa"
	"log"
)

func main() {
	keys, err := rsa.GenerateKeys(2048)

	if err != nil {
		log.Fatal(err)
	}

	cipherText, err := rsa.Encrypt("message", keys.PublicKey, keys.N)

	if err != nil {
		log.Fatal(err)
	}

	plainText, err := rsa.Decrypt(cipherText, keys.PrivateKey, keys.N)

	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(cipherText)
	fmt.Println(plainText)

	json := map[string]interface{}{
		"name":    "Alice",
		"age":     30,
		"height":  5.7,
		"address": map[string]interface{}{"city": "Wonderland", "zip": 12345},
		"items":   []interface{}{"apple", "banana", 42, 3.14},
	}

	encryptedJSON, err := rsa.EncryptStruct(json, keys.PublicKey, keys.N)

	if err != nil {
		log.Fatalf("Error encrypting JSON: %s", err)
	}

	encryptedMarshalledJSON, err := json2.Marshal(encryptedJSON)

	if err != nil {
		log.Fatalf("Error marshaling encrypted JSON: %s", err)
	}

	fmt.Println(string(encryptedMarshalledJSON))

	decryptedJSON, err := rsa.DecryptStruct(encryptedJSON, keys.PrivateKey, keys.N)

	if err != nil {
		log.Fatalf("Error decrypting JSON: %s", err)
	}

	decryptedMarshalledJSON, err := json2.Marshal(decryptedJSON)

	if err != nil {
		log.Fatalf("Error marshaling decrypted JSON: %s", err)
	}

	fmt.Println(string(decryptedMarshalledJSON))
}
