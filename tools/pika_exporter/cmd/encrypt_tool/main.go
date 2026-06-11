package main

import (
	"fmt"
	"os"

	"github.com/OpenAtomFoundation/pika/tools/pika_exporter/exporter"
)

func main() {
	if len(os.Args) < 3 {
		fmt.Println("Pika Exporter Password Encryption Tool")
		fmt.Println()
		fmt.Println("Usage:")
		fmt.Println("  pika_encrypt_tool -password <plaintext_password> -key <encryption_key>")
		fmt.Println()
		fmt.Println("Options:")
		fmt.Println("  -password  The plaintext password to encrypt (required)")
		fmt.Println("  -key       The encryption key (16, 24, or 32 characters for AES-128/192/256)")
		fmt.Println("             If shorter than 16 chars, it will be padded. If longer than 32, it will be truncated.")
		fmt.Println()
		fmt.Println("Examples:")
		fmt.Println("  pika_encrypt_tool -password mysecret -key my16charkey12345")
		fmt.Println()
		fmt.Println("The encrypted password can then be used with:")
		fmt.Println("  pika_exporter -pika.password=<encrypted> -pika.password-key=<key>")
		fmt.Println("  pika_exporter -pika.password-file=<password_file> -pika.password-key=<key>")
		os.Exit(1)
	}

	var plaintext, key string
	for i := 1; i < len(os.Args); i++ {
		switch os.Args[i] {
		case "-password":
			if i+1 < len(os.Args) {
				plaintext = os.Args[i+1]
				i++
			}
		case "-key":
			if i+1 < len(os.Args) {
				key = os.Args[i+1]
				i++
			}
		}
	}

	if plaintext == "" {
		fmt.Fprintln(os.Stderr, "Error: -password is required")
		os.Exit(1)
	}
	if key == "" {
		fmt.Fprintln(os.Stderr, "Error: -key is required")
		os.Exit(1)
	}

	paddedKey := exporter.PadKey(key)
	encrypted, err := exporter.EncryptPassword(plaintext, paddedKey)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error encrypting password: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("Encrypted password:", encrypted)
	fmt.Println()
	fmt.Println("You can now use it in one of the following ways:")
	fmt.Println()
	fmt.Println("1. Command line with encrypted password:")
	fmt.Printf("   pika_exporter -pika.password=%s -pika.password-key=%s\n", encrypted, key)
	fmt.Println()
	fmt.Println("2. Password file (write the encrypted password to a file):")
	fmt.Printf("   echo '%s' > /path/to/password_file\n", encrypted)
	fmt.Printf("   pika_exporter -pika.password-file=/path/to/password_file -pika.password-key=%s\n", key)
	fmt.Println()
	fmt.Println("3. Environment variable:")
	fmt.Printf("   export PIKA_PASSWORD=%s\n", encrypted)
	fmt.Printf("   export PIKA_PASSWORD_KEY=%s\n", key)
	fmt.Println("   pika_exporter")
}
