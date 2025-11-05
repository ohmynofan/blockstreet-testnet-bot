package worker

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	crand "crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"sync"
	"time"
)

type blockStreetEncryptedPayload struct {
	cipherText   string
	iv           string
	encryptedKey string
	timestamp    int64
}

var (
	blockStreetRSAKeysOnce sync.Once
	blockStreetRSAKeys     []*rsa.PublicKey
	blockStreetRSAKeysErr  error

	blockStreetVisitorOnce sync.Once
	blockStreetVisitorID   string
)

var blockStreetRSAPublicKeys = []string{
	`-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAxX8AFdH2X9GmVO50msDy
zAcfdhNwNQsjHLSk1NVk/EkrEGngajAydd9/DN7FdtUck816riO20/uhwqFfEPb3
Nd74t3DBM2TLvw4foVbssaR9SER2G0DJOi5bKEDNhaVeg03H1/X1/qZiKv38LSwY
VgWi+yiVJ1n18elbE5NRD2Wv2ybqdZ2TIVOIrGtneUhbN0CrrxdeuO0/yqitohnC
Bm+rwQO4FXqnD3MKmCTBQD8bBFWaHw2ow2CX8vXMuPJBYEk0b8tYMzbxWJUnoVDq
tDjYj5L10R/MtFDRvaRG/E3igTcYF0QRPfvP78kCwY2QIXnRZEjliEfoku42YL0R
ZwIDAQAB
-----END PUBLIC KEY-----`,
	`-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAxkEVgGx/dKn8axHe0B3T
yCqHjE62ofCO8E8mCKsZj7Kx/wTHqKAZpF/55pFGkF3gr9sLLQcx21VfEZsGIJ8q
YOndyZDuB06b5JE0Xu26g5iwMW/xkBtIm8eMr8L+ApHU2hml0KqHGdULeSNcLRiu
CHGnP+W2zjLnzl47HTNPPEFkFbSe8RBVQ0SediY+RzLVFX89Tpt3NMMvYs8ng9wi
/cDIbUXgMIpYdiHfaW28X9GoUXKJmP4pB5rEXk0J22bKcRsopECOudu5Am4dCrDn
kbxrUxQR4dNSiyOKFkarARvkWOukcvNXHTg58z6+uzg9kVRSaVV2hShoY0Dwfg++
qwIDAQAB
-----END PUBLIC KEY-----`,
	`-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAnzpG+3W5mvFXBmJSDiDc
VyEZrR7rsJHHNb7bPLPSdwDBDfrg3EaPH88WAhLMqHx2MwSPLcG44eU7ICJ/l0xL
hZGx8NiqZnkwKrOKzBUyY6+ZlaOZZvRp9WTP+vVDeApW+3dftq8jJm9C1F+2v6cU
8VXjEnH/QVx6I/7zhdf15aQxm28JTj5z1jlfER04qUWZV+EcktG/f7frjYw0YhsZ
HqzeKwU0ggUiIDfcXlsNRbx4rrFwh1+c1Yy8ctb3+PQY8/EOgVgEEKPR1vFnC6me
R4ooXjx9psXL2dt37+8BOi1Ja/ruG6uoCJKr7jMF7dND5p0kbbAZPHfZKoiYAKhc
bwIDAQAB
-----END PUBLIC KEY-----`,
}

func ensureBlockStreetRSAKeys() error {
	blockStreetRSAKeysOnce.Do(func() {
		keys := make([]*rsa.PublicKey, 0, len(blockStreetRSAPublicKeys))
		for idx, pemStr := range blockStreetRSAPublicKeys {
			block, _ := pem.Decode([]byte(pemStr))
			if block == nil {
				blockStreetRSAKeysErr = fmt.Errorf("failed to decode RSA public key at index %d", idx)
				return
			}
			pubKey, err := x509.ParsePKIXPublicKey(block.Bytes)
			if err != nil {
				blockStreetRSAKeysErr = fmt.Errorf("failed to parse RSA public key at index %d: %w", idx, err)
				return
			}
			rsaPub, ok := pubKey.(*rsa.PublicKey)
			if !ok {
				blockStreetRSAKeysErr = fmt.Errorf("unexpected RSA public key type at index %d: %T", idx, pubKey)
				return
			}
			keys = append(keys, rsaPub)
		}
		blockStreetRSAKeys = keys
	})
	return blockStreetRSAKeysErr
}

func encryptSignVerifyPayload(payload signVerifyPayload) (blockStreetEncryptedPayload, error) {
	if err := ensureBlockStreetRSAKeys(); err != nil {
		return blockStreetEncryptedPayload{}, err
	}

	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		return blockStreetEncryptedPayload{}, fmt.Errorf("failed to marshal signverify payload: %w", err)
	}

	aesKey := make([]byte, 32)
	if _, err := crand.Read(aesKey); err != nil {
		return blockStreetEncryptedPayload{}, fmt.Errorf("failed to generate AES key: %w", err)
	}

	iv := make([]byte, aes.BlockSize)
	if _, err := crand.Read(iv); err != nil {
		return blockStreetEncryptedPayload{}, fmt.Errorf("failed to generate AES IV: %w", err)
	}

	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return blockStreetEncryptedPayload{}, fmt.Errorf("failed to initialize AES cipher: %w", err)
	}

	padded := pkcs7Pad(payloadJSON, block.BlockSize())
	ciphertext := make([]byte, len(padded))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(ciphertext, padded)

	timestamp := time.Now().UnixMilli()
	if timestamp < 0 {
		timestamp = time.Now().UTC().UnixMilli()
	}

	index := indexForTimestamp(timestamp, len(blockStreetRSAKeys))
	if index < 0 || index >= len(blockStreetRSAKeys) {
		return blockStreetEncryptedPayload{}, fmt.Errorf("rsa key index out of bounds: %d", index)
	}

	aesKeyBase64 := base64.StdEncoding.EncodeToString(aesKey)
	encryptedKey, err := rsa.EncryptPKCS1v15(crand.Reader, blockStreetRSAKeys[index], []byte(aesKeyBase64))
	if err != nil {
		return blockStreetEncryptedPayload{}, fmt.Errorf("failed to encrypt AES key: %w", err)
	}

	return blockStreetEncryptedPayload{
		cipherText:   base64.StdEncoding.EncodeToString(ciphertext),
		iv:           base64.StdEncoding.EncodeToString(iv),
		encryptedKey: base64.StdEncoding.EncodeToString(encryptedKey),
		timestamp:    timestamp,
	}, nil
}

func indexForTimestamp(timestamp int64, modulus int) int {
	if modulus <= 0 {
		return 0
	}

	tsBig := big.NewInt(timestamp)
	two := big.NewInt(2)
	id := new(big.Int).Mul(tsBig, two)

	mod := new(big.Int).Mod(id, big.NewInt(int64(modulus)))
	return int(mod.Int64())
}

func pkcs7Pad(data []byte, blockSize int) []byte {
	if blockSize <= 0 {
		return data
	}
	padding := blockSize - len(data)%blockSize
	if padding == 0 {
		padding = blockSize
	}
	pad := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(data, pad...)
}

func blockStreetGetVisitorID() string {
	blockStreetVisitorOnce.Do(func() {
		id, err := generateVisitorID()
		if err != nil {
			blockStreetVisitorID = "00000000000000000000000000000011"
			return
		}
		blockStreetVisitorID = id
	})
	return blockStreetVisitorID
}

func generateVisitorID() (string, error) {
	for {
		buf := make([]byte, 16)
		if _, err := crand.Read(buf); err != nil {
			return "", fmt.Errorf("failed to generate visitor id bytes: %w", err)
		}

		buf[6] = (buf[6] & 0x0f) | 0x40
		buf[8] = (buf[8] & 0x3f) | 0x80

		hexStr := hex.EncodeToString(buf)
		if len(hexStr) >= 2 && hexStr[len(hexStr)-2] == '1' {
			return hexStr, nil
		}
	}
}
