package aes

import (
	"bytes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"errors"
	"hash"
	"io"
)

// cipher.AEAD is an interface that implements an Authenticated Encryption with
// Associated Data scheme. xref: https://golang.org/pkg/crypto/cipher/#AEAD
// We implement this interface as defined in RFC5116 at:
// https://tools.ietf.org/html/rfc5116 using CBC + HMAC.
// The interface definition is replicated in the block comment below for reference.
/*
type AEAD interface {
	// NonceSize returns the size of the nonce that must be passed to Seal
	// and Open.
	NonceSize() int

	// Overhead returns the maximum difference between the lengths of a
	// plaintext and its ciphertext.
	Overhead() int

	// Seal encrypts and authenticates plaintext, authenticates the
	// additional data and appends the result to dst, returning the updated
	// slice. The nonce must be NonceSize() bytes long and unique for all
	// time, for a given key.
	//
	// To reuse plaintext's storage for the encrypted output, use plaintext[:0]
	// as dst. Otherwise, the remaining capacity of dst must not overlap plaintext.
	Seal(dst, nonce, plaintext, additionalData []byte) []byte

	// Open decrypts and authenticates ciphertext, authenticates the
	// additional data and, if successful, appends the resulting plaintext
	// to dst, returning the updated slice. The nonce must be NonceSize()
	// bytes long and both it and the additional data must match the
	// value passed to Seal.
	//
	// To reuse ciphertext's storage for the decrypted output, use ciphertext[:0]
	// as dst. Otherwise, the remaining capacity of dst must not overlap plaintext.
	//
	// Even if the function fails, the contents of dst, up to its capacity,
	// may be overwritten.
	Open(dst, nonce, ciphertext, additionalData []byte) ([]byte, error)
}
*/

// aesCbcHmac represents an AES block cipher in CBC mode authenticated with HMAC data
type aesCbcHmac struct {
	cipher    cipher.Block
	hash      hash.Hash
	nonceSize int
	tagSize   int
}

const (
	achBlockSize         = 16
	achTagSize           = 16
	achMinimumTagSize    = 12 // NIST SP 800-38D recommends tags with 12 or more bytes.
	achStandardNonceSize = 12
)

// NewACH returns an AEAD which uses the AES block cipher in CBC mode authenticated with HMAC data
func NewACH(cipher cipher.Block, hash hash.Hash) (cipher.AEAD, error) {
	return newACHWithNonceAndTagSize(cipher, hash, achStandardNonceSize, achTagSize)
}

func newACHWithNonceAndTagSize(cipher cipher.Block, hash hash.Hash, nonceSize int, tagSize int) (cipher.AEAD, error) {
	if tagSize < achMinimumTagSize || tagSize > achBlockSize || tagSize > hash.Size() {
		return nil, errors.New("aes-cbc-hmac: incorrect tag size given")
	}

	if cipher.BlockSize() != achBlockSize {
		return nil, errors.New("aes-cbc-hmac: requires 128-bit block cipher")
	}

	ach := &aesCbcHmac{cipher: cipher, hash: hash, nonceSize: nonceSize, tagSize: tagSize}
	return ach, nil
}

func (ach *aesCbcHmac) NonceSize() int {
	return ach.nonceSize
}

func (ach *aesCbcHmac) Overhead() int {
	return ach.tagSize
}

func (ach *aesCbcHmac) Seal(dst, nonce, plaintext, data []byte) []byte {
	if len(nonce) != ach.nonceSize {
		panic("aes-cbc-hmac: Nonce Length does not match!")
	}
	if uint64(len(plaintext)) > ((1<<32)-2)*uint64(ach.cipher.BlockSize()) {
		panic("aes-cbc-hmac: message is too large")
	}

	blockSize := achBlockSize
	paddingSize := blockSize - (len(plaintext) % blockSize)
	result := make([]byte, blockSize+len(plaintext)+paddingSize)

	// Generate random bytes for iv in first block
	iv := result[:blockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		panic("aes-cbc-hmac: unable to read sufficient random bytes")
	}

	// Copy actual plaintext
	copy(result[blockSize:], plaintext)

	// add PKCS#7 padding for CBC
	copy(result[blockSize+len(plaintext):], bytes.Repeat([]byte{byte(paddingSize)}, paddingSize))

	// Encrypt
	mode := cipher.NewCBCEncrypter(ach.cipher, iv)
	mode.CryptBlocks(result[blockSize:], result[blockSize:])

	// Then MAC
	// Calculate HMAC input as nonce N + Associated data A + ciphertext
	// Refer to RFC5116 at: https://tools.ietf.org/html/rfc5116
	hmacInput := make([]byte, len(nonce)+len(data)+len(result))
	copy(hmacInput, nonce)
	hmacInput = append(hmacInput, data...)
	hmacInput = append(hmacInput, result...)
	ach.hash.Write(hmacInput)
	tag := ach.hash.Sum(nil)
	ach.hash.Reset()

	// Truncate HMAC to tagsize
	tag = tag[:ach.tagSize]

	result = append(result, tag...)
	copy(dst, result)
	return result
}

var errOpen = errors.New("aes-cbc-hmac: AEAD - Open failed")

func (ach *aesCbcHmac) Open(dst, nonce, ciphertext, data []byte) ([]byte, error) {
	if len(nonce) != ach.nonceSize {
		panic("aes-cbc-hmac: Nonce Length does not match!")
	}

	if len(ciphertext) < ach.tagSize {
		return nil, errOpen
	}

	if uint64(len(ciphertext)) > ((1<<32)-2)*uint64(ach.cipher.BlockSize())+uint64(ach.tagSize) {
		return nil, errOpen
	}

	tag := ciphertext[len(ciphertext)-ach.tagSize:]
	ciphertext = ciphertext[:len(ciphertext)-ach.tagSize]

	// Calculate tag to compare with actual tag
	// HMAC input is nonce N + Associated data A + ciphertext
	// Refer to RFC5116 at: https://tools.ietf.org/html/rfc5116
	hmacInput := make([]byte, len(nonce)+len(data)+len(ciphertext))
	copy(hmacInput, nonce)
	hmacInput = append(hmacInput, data...)
	hmacInput = append(hmacInput, ciphertext...)

	ach.hash.Write(hmacInput)
	evaluatedTag := ach.hash.Sum(nil)
	ach.hash.Reset()

	// Truncate HMAC to tagsize
	evaluatedTag = evaluatedTag[:ach.tagSize]

	// Compare tags
	if !hmac.Equal(tag, evaluatedTag) {
		return nil, errOpen
	}

	// iff tag is valid, only then we proceed with decryption
	return ach.decryptCiphertext(ciphertext)
}

// Helper function to decrypt the ciphertext, verify and strip
// the PKCS#7 padding and return the resulting plaintext
func (ach *aesCbcHmac) decryptCiphertext(cipherText []byte) ([]byte, error) {
	iv := cipherText[:achBlockSize]
	cipherText = cipherText[achBlockSize:]

	// Ciphertext should be an even multiple of block size
	if len(cipherText)%achBlockSize != 0 {
		return nil, errOpen
	}

	result := make([]byte, len(cipherText))
	copy(result, cipherText)
	mode := cipher.NewCBCDecrypter(ach.cipher, iv)
	mode.CryptBlocks(result, result)

	// Remove and verify PKCS#7 padding for cbc
	c := result[len(result)-1]
	paddingSize := int(c)
	size := len(result) - paddingSize
	err := error(nil)

	if paddingSize == 0 || paddingSize > len(result) {
		err = errOpen
	}
	for i := 0; i < paddingSize; i++ {
		if result[size+i] != c {
			err = errOpen
		}
	}

	// If there are issues with the PKCS#7 padding return error
	if err != nil {
		return nil, err
	}

	return result[:size], nil

}
