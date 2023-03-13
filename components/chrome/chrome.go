package chrome

import (
	"crypto/aes"
	"crypto/cipher"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/Blank-c/PassView/util"
	_ "github.com/mattn/go-sqlite3"
	"github.com/zavla/dpapi"
)

type ChromePasswordFormat struct {
	URL, Username, Password string
}

var (
	EncryptionKey []byte
	Path          string
)

func init() {
	Path = filepath.Join(os.Getenv("LOCALAPPDATA"), "Google", "Chrome", "User Data")
}

func getEncryptionKey() ([]byte, error) {
	if EncryptionKey != nil {
		return EncryptionKey, nil
	}

	var jsonContent map[string]any
	var encryptionKey []byte

	localStatePath := filepath.Join(Path, "Local State")
	if _, err := os.Stat(localStatePath); err != nil {
		return nil, err
	}

	file, err := os.Open(localStatePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	content, err := io.ReadAll(file)
	if err != nil {
		return nil, err
	}

	if err = json.Unmarshal(content, &jsonContent); err != nil {
		return nil, err
	}

	if key, ok := jsonContent["os_crypt"]; ok {
		if key, ok = key.(map[string]any)["encrypted_key"]; ok {
			encryptionKey, err = base64.StdEncoding.DecodeString(key.(string))
			if err != nil {
				return nil, err
			} else {
				encryptionKey = encryptionKey[5:]
			}
		} else {
			return nil, errors.New(`key "encrypted_key" not found`)
		}
	} else {
		return nil, errors.New(`key "os_crypt" not found`)
	}

	encryptionKey, err = dpapi.Decrypt(encryptionKey)
	if err != nil {
		return nil, err
	}

	EncryptionKey = encryptionKey
	return encryptionKey, nil
}

func decryptData(data []byte) (string, error) {
	key, err := getEncryptionKey()
	if err != nil {
		return "", err
	}
	if len(data) < 16 {
		return "", errors.New("encrypted data too short")
	}
	iv := data[3:15]
	data = data[15:]
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	GCMcipher, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	decryptedData, err := GCMcipher.Open(nil, iv, data, nil)
	if err != nil {
		return "", nil
	}

	return string(decryptedData), nil
}

func GetPasswords() ([]ChromePasswordFormat, error) {
	if dir, err := os.Stat(Path); err != nil || !dir.IsDir() {
		return nil, errors.New("chrome path not found")
	}

	passwords := []ChromePasswordFormat{}
	loginDataPath := []string{}

	err := filepath.Walk(Path, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if !info.IsDir() && strings.ToLower(info.Name()) == "login data" {
			loginDataPath = append(loginDataPath, path)
		}

		return nil
	})

	if err != nil {
		return nil, err
	}

	for _, path := range loginDataPath {
		tempPath := filepath.Join(os.Getenv("temp"), "vault"+util.GenerateRandomString(5))
		if err := util.CopyFile(path, tempPath); err != nil {
			continue
		}
		defer os.Remove(tempPath)

		db, err := sql.Open("sqlite3", tempPath)
		if err != nil {
			continue
		}
		defer db.Close()

		rows, err := db.Query("SELECT origin_url, username_value, password_value FROM logins")
		if err != nil {
			continue
		}
		defer rows.Close()

		for rows.Next() {
			var url, username string
			var password []byte

			if err := rows.Scan(&url, &username, &password); err != nil {
				continue
			}

			decryptedPassword, err := decryptData(password)
			if err != nil {
				continue
			}

			if url != "" && username != "" && decryptedPassword != "" {
				passwords = append(passwords, ChromePasswordFormat{url, username, decryptedPassword})
			}
		}

	}

	return passwords, nil

}
