package components

import (
	"crypto/rand"
	"encoding/base64"
	"io"
	"os"
)

func generateRandomString(length int) string {
	randomBytes := make([]byte, length)
	_, err := rand.Read(randomBytes)
	if err != nil {
		panic(err)
	}

	randomString := base64.URLEncoding.EncodeToString(randomBytes)

	return randomString[:length]
}

func copyFile(src, dst string) error {
	srcFile, err := os.Open(src)
	if err != nil {
		return err
	}
	defer srcFile.Close()

	dstFile, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer dstFile.Close()

	_, err = io.Copy(dstFile, srcFile)
	if err != nil {
		return err
	}

	err = dstFile.Sync()
	if err != nil {
		return err
	}

	fileInfo, err := os.Stat(src)
	if err != nil {
		return err
	}

	err = os.Chmod(dst, fileInfo.Mode())
	if err != nil {
		return err
	}

	return nil
}
