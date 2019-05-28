/*
Copyright 2017 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

// Package aes transforms values for storage at rest using AES-GCM.
package aes

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"fmt"
	"hash"
	"io"

	"k8s.io/apiserver/pkg/storage/value"
)

// gcm implements AEAD encryption of the provided values given a cipher.Block algorithm.
// The authenticated data provided as part of the value.Context method must match when the same
// value is set to and loaded from storage. In order to ensure that values cannot be copied by
// an attacker from a location under their control, use characteristics of the storage location
// (such as the etcd key) as part of the authenticated data.
//
// Because this mode requires a generated IV and IV reuse is a known weakness of AES-GCM, keys
// must be rotated before a birthday attack becomes feasible. NIST SP 800-38D
// (http://csrc.nist.gov/publications/nistpubs/800-38D/SP-800-38D.pdf) recommends using the same
// key with random 96-bit nonces (the default nonce length) no more than 2^32 times, and
// therefore transformers using this implementation *must* ensure they allow for frequent key
// rotation. Future work should include investigation of AES-GCM-SIV as an alternative to
// random nonces.
type gcm struct {
	block cipher.Block
}

// NewGCMTransformer takes the given block cipher and performs encryption and decryption on the given
// data.
func NewGCMTransformer(block cipher.Block) value.Transformer {
	return &gcm{block: block}
}

func (t *gcm) TransformFromStorage(data []byte, context value.Context) ([]byte, bool, error) {
	aead, err := cipher.NewGCM(t.block)
	if err != nil {
		return nil, false, err
	}
	nonceSize := aead.NonceSize()
	if len(data) < nonceSize {
		return nil, false, fmt.Errorf("the stored data was shorter than the required size")
	}
	result, err := aead.Open(nil, data[:nonceSize], data[nonceSize:], context.AuthenticatedData())
	return result, false, err
}

func (t *gcm) TransformToStorage(data []byte, context value.Context) ([]byte, error) {
	aead, err := cipher.NewGCM(t.block)
	if err != nil {
		return nil, err
	}
	nonceSize := aead.NonceSize()
	result := make([]byte, nonceSize+aead.Overhead()+len(data))
	n, err := rand.Read(result[:nonceSize])
	if err != nil {
		return nil, err
	}
	if n != nonceSize {
		return nil, fmt.Errorf("unable to read sufficient random bytes")
	}
	cipherText := aead.Seal(result[nonceSize:nonceSize], result[:nonceSize], data, context.AuthenticatedData())
	return result[:nonceSize+len(cipherText)], nil
}

// cbc implements encryption at rest of the provided values given a cipher.Block algorithm.
type cbc struct {
	block cipher.Block
	hash  hash.Hash
}

// NewCBCTransformer takes the given block cipher and performs encryption and decryption on the given
// data.
func NewCBCTransformer(block cipher.Block) value.Transformer {
	return &cbc{block: block}
}

// TODO: find out if there's a way to ensure that hash is a hmac
func NewACHTransformer(block cipher.Block, hash hash.Hash) value.Transformer {
	return &cbc{block: block, hash: hash}
}

var (
	errInvalidBlockSize = fmt.Errorf("the stored data is not a multiple of the block size")
	errFailedDecryption = fmt.Errorf("failed to decrypt stored data")
)

func (t *cbc) TransformFromStorage(data []byte, context value.Context) ([]byte, bool, error) {
	blockSize := aes.BlockSize
	// using mac only when hash is defined in cbc struct
	hashSize := 0
	if t.hash != nil {
		hashSize = t.hash.Size()
	}
	macIndex := len(data) - hashSize
	minDataSize := blockSize + hashSize
	if len(data) < minDataSize {
		return nil, false, fmt.Errorf("the stored data was shorter than the required size")
	}
	iv := data[:blockSize]
	cipherText := data[blockSize:macIndex]

	if len(cipherText)%blockSize != 0 {
		return nil, false, errInvalidBlockSize
	}

	result := make([]byte, len(cipherText))
	copy(result, cipherText)
	mode := cipher.NewCBCDecrypter(t.block, iv)
	mode.CryptBlocks(result, result)

	// remove and verify PKCS#7 padding for CBC
	c := result[len(result)-1]
	paddingSize := int(c)
	size := len(result) - paddingSize
	err := error(nil)
	if paddingSize == 0 || paddingSize > len(result) {
		err = errFailedDecryption
	}
	for i := 0; i < paddingSize; i++ {
		if result[size+i] != c {
			err = errFailedDecryption
		}
	}

	if t.hash != nil {
		mac := data[macIndex:]
		// ref Sum() in https://golang.org/pkg/hash/#Hash for why copy() is used
		macInput := make([]byte, len(data[:macIndex]))
		copy(macInput, data[:macIndex])
		if authenticatedData := context.AuthenticatedData(); authenticatedData != nil {
			macInput = append(macInput, authenticatedData...)
		}
		expectedMAC := t.getMAC(macInput)
		if !hmac.Equal(mac, expectedMAC) {
			err = errFailedDecryption
		}
	}

	if err != nil {
		return nil, false, err
	}
	return result[:size], false, nil
}

func (t *cbc) getMAC(data []byte) []byte {
	t.hash.Write(data)
	mac := t.hash.Sum(nil)
	t.hash.Reset()
	// ref https://golang.org/src/crypto/hmac/hmac.go for why Reset() is used
	// mac of same message was giving a differnt output each time without this
	return mac
}

func (t *cbc) TransformToStorage(data []byte, context value.Context) ([]byte, error) {
	blockSize := aes.BlockSize
	paddingSize := blockSize - (len(data) % blockSize)
	result := make([]byte, blockSize+len(data)+paddingSize)
	iv := result[:blockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, fmt.Errorf("unable to read sufficient random bytes")
	}
	copy(result[blockSize:], data)

	// add PKCS#7 padding for CBC
	copy(result[blockSize+len(data):], bytes.Repeat([]byte{byte(paddingSize)}, paddingSize))

	mode := cipher.NewCBCEncrypter(t.block, iv)
	mode.CryptBlocks(result[blockSize:], result[blockSize:])

	// add MAC if hash function defined
	if t.hash != nil {
		macInput := result
		if authenticatedData := context.AuthenticatedData(); authenticatedData != nil {
			macInput = append(macInput, authenticatedData...)
		}
		mac := t.getMAC(macInput)
		result = append(result, mac...)
	}
	return result, nil
}
