package shieldlist

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
)

// AppConfig is what an app needs to find its nodes. SealConfig packs it into one opaque string so the names
// and keys do not sit in the app package as plain text (grep and "strings" find nothing). The passphrase is
// in the app too, so this only stops casual scraping, not someone who reverses the app.
type AppConfig struct {
	Name      string   `json:"n"`           // first name to read the list from
	Fallbacks []string `json:"f,omitempty"` // backup names
	PublicKey string   `json:"k"`           // list verification key (base64)
	ListKey   string   `json:"l,omitempty"` // list seal key (base64), when the list is sealed
}

func configKey(pass string) []byte {
	h := sha256.Sum256([]byte("gamec-config\x00" + pass))
	return h[:]
}

// SealConfig is base64url(nonce || AES-256-GCM(json)) under SHA-256("gamec-config\0" + pass).
func SealConfig(pass string, c AppConfig) (string, error) {
	if pass == "" || c.Name == "" || c.PublicKey == "" {
		return "", errors.New("passphrase, name and public key are required")
	}
	plain, err := json.Marshal(c)
	if err != nil {
		return "", err
	}
	aead, err := gcm(configKey(pass))
	if err != nil {
		return "", err
	}
	nonce, err := NewSealKey()
	if err != nil {
		return "", err
	}
	nonce = nonce[:aead.NonceSize()]
	return base64.RawURLEncoding.EncodeToString(aead.Seal(nonce, nonce, plain, nil)), nil
}

// OpenConfig is the inverse of SealConfig (what the apps do).
func OpenConfig(pass, blob string) (*AppConfig, error) {
	raw, err := base64.RawURLEncoding.DecodeString(blob)
	if err != nil {
		return nil, errors.New("config is not base64")
	}
	aead, err := gcm(configKey(pass))
	if err != nil {
		return nil, err
	}
	if len(raw) <= aead.NonceSize() {
		return nil, errors.New("config too short")
	}
	plain, err := aead.Open(nil, raw[:aead.NonceSize()], raw[aead.NonceSize():], nil)
	if err != nil {
		return nil, errors.New("wrong passphrase or damaged config")
	}
	var c AppConfig
	if err := json.Unmarshal(plain, &c); err != nil || c.Name == "" || c.PublicKey == "" {
		return nil, errors.New("bad config")
	}
	return &c, nil
}
