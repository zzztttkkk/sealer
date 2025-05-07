package sealer

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"
)

func pkcs7Padding(data []byte, blockSize int) []byte {
	padding := blockSize - len(data)%blockSize
	padText := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(data, padText...)
}

func pkcs7Unpadding(data []byte) ([]byte, error) {
	length := len(data)
	if length == 0 {
		return nil, fmt.Errorf("invalid padding size")
	}
	unpadding := int(data[length-1])
	if unpadding > length {
		return nil, fmt.Errorf("unpadding size too large")
	}
	return data[:(length - unpadding)], nil
}

func AesEncrypt(input []byte, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	size := block.BlockSize()
	padded := pkcs7Padding(input, size)
	iv := make([]byte, size)
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, err
	}
	mode := cipher.NewCBCEncrypter(block, iv)
	clip := make([]byte, len(padded))
	mode.CryptBlocks(clip, padded)
	return append(iv, clip...), nil
}

func AesDecrypt(input []byte, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	blockSize := block.BlockSize()
	if len(input) < blockSize {
		return nil, fmt.Errorf("ciphertext too short")
	}
	iv := input[:blockSize]
	ciphertext := input[blockSize:]

	if len(ciphertext)%blockSize != 0 {
		return nil, fmt.Errorf("ciphertext is not a multiple of the block size")
	}

	mode := cipher.NewCBCDecrypter(block, iv)
	plaintext := make([]byte, len(ciphertext))
	mode.CryptBlocks(plaintext, ciphertext)

	plaintext, err = pkcs7Unpadding(plaintext)
	if err != nil {
		return nil, err
	}
	return plaintext, nil
}
