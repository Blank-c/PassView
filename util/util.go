package util

import (
	"crypto/rand"
	"encoding/base64"
	"io"
	"os"
)

// Source: ChatGPT
func GenerateRandomString(length int) string {
	// Generate a random byte slice of the specified length
	randomBytes := make([]byte, length)
	_, err := rand.Read(randomBytes)
	if err != nil {
		panic(err)
	}

	// Convert the random byte slice to a base64-encoded string
	randomString := base64.URLEncoding.EncodeToString(randomBytes)

	// Trim any trailing padding characters from the string
	return randomString[:length]
}

// Source: ChatGPT
func CopyFile(src, dst string) error {
	// Open the source file for reading
	srcFile, err := os.Open(src)
	if err != nil {
		return err
	}
	defer srcFile.Close()

	// Create the destination file for writing
	dstFile, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer dstFile.Close()

	// Copy the contents of the source file to the destination file
	_, err = io.Copy(dstFile, srcFile)
	if err != nil {
		return err
	}

	// Sync the destination file to ensure that all data has been written
	err = dstFile.Sync()
	if err != nil {
		return err
	}

	// Get the file information for the source file
	fileInfo, err := os.Stat(src)
	if err != nil {
		return err
	}

	// Set the permissions of the destination file to match the source file
	err = os.Chmod(dst, fileInfo.Mode())
	if err != nil {
		return err
	}

	return nil
}
