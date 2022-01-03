package sopsdecryptor

import (
	"errors"
	"fmt"
	"go.mozilla.org/sops/v3"
	"go.mozilla.org/sops/v3/aes"
	"go.mozilla.org/sops/v3/cmd/sops/common"
	. "go.mozilla.org/sops/v3/cmd/sops/formats"
	"io/ioutil"
	"os"
	"time"
)

type Decryptor struct {
	encryptedFilePath string
	decryptedData     []byte
	tree              sops.Tree
	format            string
	fmt               Format
}

// NewDecoder Create a new decryptor instance
func NewDecoder(encryptedFilePath string) (*Decryptor, error) {
	var decoder = &Decryptor{}
	decoder.encryptedFilePath = encryptedFilePath
	decoder.fmt = FormatForPath(encryptedFilePath)
	if err := decoder.decryptFile(); err != nil {
		return nil, err
	}
	return decoder, nil
}

// PrintDecryptedFile Just print content of the decrypted file
func (d *Decryptor) PrintDecryptedFile() {
	fmt.Printf("%s\n", d.decryptedData)
}

// ExposeEnvVariables Expose decrypted ENV file as environment variables
func (d *Decryptor) ExposeEnvVariables() error {
	if d.fmt != Dotenv {
		return fmt.Errorf("this isn't ENV file")
	}
	for _, branch := range d.tree.Branches {
		for _, item := range branch {
			varName := fmt.Sprintf("%s", item.Key)
			varVal := fmt.Sprintf("%s", item.Value)
			if err := os.Setenv(varName, varVal); err != nil {
				return err
			}
		}
	}
	return nil
}

// DumpDecodedFile Dump decrypted file to the provided local filesystem path
func (d *Decryptor) DumpDecodedFile(path string) error {
	if err := ioutil.WriteFile(path, d.decryptedData, 0775); err != nil {
		return err
	}
	return nil
}

func (d *Decryptor) decryptFile() error {
	encryptedData, err := ioutil.ReadFile(d.encryptedFilePath)
	if err != nil {
		return fmt.Errorf("Failed to read %q: %w", d.encryptedFilePath, err)
	}

	store := common.StoreForFormat(d.fmt)
	// Load SOPS file and access the data key
	tree, err := store.LoadEncryptedFile(encryptedData)
	if err != nil {
		return err
	}
	key, err := tree.Metadata.GetDataKey()
	if err != nil {
		return err
	}
	//Decrypt the tree
	cipher := aes.NewCipher()
	mac, err := tree.Decrypt(key, cipher)
	if err != nil {
		return err
	}
	originalMac, err := cipher.Decrypt(
		tree.Metadata.MessageAuthenticationCode,
		key,
		tree.Metadata.LastModified.Format(time.RFC3339),
	)
	if originalMac != mac {
		return fmt.Errorf("Failed to verify data integrity. expected mac %q, got %q", originalMac, mac)
	}
	d.tree = tree
	clearText, err := store.EmitPlainFile(tree.Branches)
	if err != nil {
		return err
	}
	d.decryptedData = clearText
	return nil
}

func EncryptedFilePath() (string, error) {
	path, ok := os.LookupEnv("ENC_FILE_PATH")
	if !ok {
		return "", errors.New("ENC_FILE_PATH is undefined")
	}
	return path, nil
}
