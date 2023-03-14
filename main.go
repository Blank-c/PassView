package main

import (
	"fmt"

	"github.com/Blank-c/PassView/components"
)

func main() {
	passwords := []components.PasswordModel{}

	chromePasswords := make(chan []components.PasswordModel)
	go components.GetChromePasswords(chromePasswords)

	for _, item := range append(passwords, <-chromePasswords...) {
		fmt.Printf("URL: %s\nUsername: %s\nPassword: %s\n\n", item.URL, item.Username, item.Password)
	}
}
