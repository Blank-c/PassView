package main

import (
	"fmt"
	"log"

	"github.com/Blank-c/PassView/components/chrome"
)

func main() {
	passwords, err := chrome.GetPasswords()
	if err != nil {
		log.Fatal(err)
	}
	for _, item := range passwords {
		fmt.Printf("URL: %s\nUsername: %s\nPassword: %s\n\n", item.URL, item.Username, item.Password)
	}
}
