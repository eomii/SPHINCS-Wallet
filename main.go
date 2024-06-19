package main

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"encoding/json"
	"falconWallet/address"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"strconv"
	"strings"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/open-quantum-safe/liboqs-go/oqs"
)

type Signature struct {
	OriginalMessage string   `json:"originalMessage"`
	Message         []byte   `json:"message"`
	PubKey          []byte   `json:"pubKey"`
	Signature      []byte   `json:"signature"`
}

type CombinedKey struct {
	SecretKey []byte `json:"secretKey"`
	PublicKey []byte `json:"publicKey"`
}

func main() {
	fmt.Println("This is an experimental mini-wallet using SPHINCS+-SHA2-128s-simple. Do not use in production.")

	const sigName = "SPHINCS+-SHA2-128s-simple"
	var signer oqs.Signature
	defer signer.Clean()

	var pubKey []byte // Store the public key here

	for {
		fmt.Println("1. Generate a new wallet")
		fmt.Println("2. Import a wallet")
		fmt.Println("3. Exit")

		choice, err := getUserChoice()
		if err != nil {
			fmt.Println("Invalid input. Please enter a number.")
			continue
		}

		switch choice {
		case 1:
			if err := signer.Init(sigName, nil); err != nil {
				log.Fatal(err)
			}
			pubKey, err = signer.GenerateKeyPair()
			if err != nil {
				log.Fatal(err)
			}
			hexPubKey := hex.EncodeToString(pubKey)
			fmt.Println("Signer public key: ", hexPubKey)
			addr, err := address.PubToAddress(pubKey)
			if err != nil {
				log.Fatal(err)
			}
			fmt.Println("Signer Address: ", hex.EncodeToString(addr))
			goto mainLoop
		case 2:
			fmt.Print("Enter the path to your keypair.json file: ")
			reader := bufio.NewReader(os.Stdin)
			filePath, _ := reader.ReadString('\n')
			filePath = strings.TrimSpace(filePath)

			// Load the key pair from the file
			if err := loadKeyPair(&signer, &pubKey, filePath); err != nil {
				fmt.Println("Error importing key pair:", err)
				continue // Go back to the main menu
			}
			fmt.Println("Key pair imported successfully!")
			goto mainLoop
		case 3:
			os.Exit(0)
		default:
			fmt.Println("Invalid choice. Please enter a number between 1 and 3.")
		}
	}

mainLoop:
	for {
		fmt.Println("1. Sign a message")
		fmt.Println("2. Verify a message")
		fmt.Println("3. Export wallet")
		fmt.Println("4. Exit")

		choice, err := getUserChoice()
		if err != nil {
			fmt.Println("Invalid input. Please enter a number.")
			continue
		}

		switch choice {
		case 1:
			hashedMessage, originalMessage := generateMessage() // Get both values
			signature, err := signer.Sign(hashedMessage)
			if err != nil {
				log.Fatal(err)
			}

			sigObj := Signature{
				OriginalMessage: originalMessage, // Store the original message
				Message:         hashedMessage,
				PubKey:          pubKey,
				Signature:      signature,
			}

			sigJSON, err := json.Marshal(sigObj)
			if err != nil {
				log.Fatal(err)
			}

			fileName := "signature.json"
			if err := ioutil.WriteFile(fileName, sigJSON, 0644); err != nil {
				log.Fatal(err)
			}

			fmt.Println("Signature saved to:", fileName)

		case 2:
			var loadedSig Signature
			fileName := "signature.json"

			file, err := ioutil.ReadFile(fileName)
			if err != nil {
				log.Fatal(err)
			}

			if err := json.Unmarshal(file, &loadedSig); err != nil {
				log.Fatal(err)
			}

			verifier := oqs.Signature{}
			defer verifier.Clean()

			if err := verifier.Init(sigName, nil); err != nil {
				log.Fatal(err)
			}

			isValid, err := verifier.Verify(loadedSig.Message, loadedSig.Signature, loadedSig.PubKey)
			if err != nil {
				log.Fatal(err)
			}

			// Additional Check: Recalculate the hash and compare
			recalculatedHash := generateMessageHash(loadedSig.OriginalMessage)
			hashMatches := bytes.Equal(recalculatedHash, loadedSig.Message)

			fmt.Println("Valid signature?", isValid)
			fmt.Println("Original message hash matches?", hashMatches)

		case 3:
			secretKey := signer.ExportSecretKey()
			combinedKey := CombinedKey{
				SecretKey: secretKey,
				PublicKey: pubKey,
			}

			keyJSON, err := json.Marshal(combinedKey)
			if err != nil {
				log.Fatal(err)
			}

			fileName := "keypair.json"
			if err := ioutil.WriteFile(fileName, keyJSON, 0644); err != nil {
				log.Fatal(err)
			}

			fmt.Println("Secret and public key saved to:", fileName)
		case 4:
			os.Exit(0)
		default:
			fmt.Println("Invalid choice. Please enter a number between 1 and 4.")
		}
	}
}

func getUserChoice() (int, error) {
	reader := bufio.NewReader(os.Stdin)
	fmt.Print("Enter your choice: ")
	input, err := reader.ReadString('\n')
	if err != nil {
		return 0, err
	}
	input = strings.TrimSpace(input)
	return strconv.Atoi(input)
}

func generateMessage() ([]byte, string) { 
	reader := bufio.NewReader(os.Stdin)
	fmt.Print("Enter a message: ")
	message, _ := reader.ReadString('\n')
	message = strings.TrimSpace(message)
	return generateMessageHash(message), message // Return both
}


func generateMessageHash(message string) []byte {
	hashedMessage := crypto.Keccak256([]byte(message))
	prefix := []byte("Qogecoin Signed Message:")
	finalMessage := crypto.Keccak256(append(prefix, hashedMessage...))
	return finalMessage
}

// Function to load the key pair from a JSON file
func loadKeyPair(signer *oqs.Signature, pubKey *[]byte, filePath string) error {
	// Read the JSON file
	keyJSON, err := ioutil.ReadFile(filePath)
	if err != nil {
		return fmt.Errorf("error reading keypair.json: %w", err)
	}

	// Unmarshal the JSON data
	var combinedKey CombinedKey
	if err := json.Unmarshal(keyJSON, &combinedKey); err != nil {
		return fmt.Errorf("error unmarshaling keypair.json: %w", err)
	}

	// Initialize the signer with the secret key
	if err := signer.Init("SPHINCS+-SHA2-128s-simple", combinedKey.SecretKey); err != nil {
		return fmt.Errorf("error initializing signer: %w", err)
	}

	// Set the public key
	*pubKey = combinedKey.PublicKey

	return nil
}