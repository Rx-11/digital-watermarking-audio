package utils

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"errors"
	"fmt"
	"log"
	"os"

	"github.com/go-audio/audio"
	"github.com/go-audio/wav"
)

func GenerateKeys() (*rsa.PrivateKey, *rsa.PublicKey) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatal(err)
	}
	return privateKey, &privateKey.PublicKey
}

func SignMessage(message []byte, privateKey *rsa.PrivateKey) ([]byte, error) {
	hash := sha256.Sum256(message)
	signature, err := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, hash[:])
	if err != nil {
		return nil, err
	}
	return signature, nil
}

func SignatureToPN(signature []byte) []int {
	pnSequence := make([]int, 0, len(signature)*8)
	for _, b := range signature {
		for i := 0; i < 8; i++ {
			if (b & (1 << i)) != 0 {
				pnSequence = append(pnSequence, 1)
			} else {
				pnSequence = append(pnSequence, -1)
			}
		}
	}
	return pnSequence
}

func VerifySignature(message, signature []byte, pubKey *rsa.PublicKey) error {
	hash := sha256.Sum256(message)
	err := rsa.VerifyPKCS1v15(pubKey, crypto.SHA256, hash[:], signature)
	return err
}

func LoadWavFile(inputFile string) (*audio.IntBuffer, error) {
	file, err := os.Open(inputFile)
	if err != nil {
		return nil, fmt.Errorf("failed to open file: %v", err)
	}
	defer file.Close()

	decoder := wav.NewDecoder(file)
	audioBuffer, err := decoder.FullPCMBuffer()
	if err != nil {
		return nil, fmt.Errorf("failed to decode WAV: %v", err)
	}

	return audioBuffer, nil
}

func PNToSignature(pnSequence []int) []byte {
	signature := make([]byte, len(pnSequence)/8)

	for i := range signature {
		var byteVal byte
		for j := 0; j < 8; j++ {
			if pnSequence[i*8+j] > 0 {
				byteVal |= (1 << j)
			}
		}
		signature[i] = byteVal
	}

	return signature
}

func VerifyWatermark(extractedPN []int, originalMessage []byte, publicKey *rsa.PublicKey) error {
	extractedSignature := PNToSignature(extractedPN)

	err := VerifySignature(originalMessage, extractedSignature, publicKey)
	if err != nil {
		return errors.New("watermark verification failed: signature mismatch")
	}

	return nil
}

func ComputeAudioHash(buffer *audio.IntBuffer) []byte {
	data := make([]byte, len(buffer.Data)*2)
	for i, sample := range buffer.Data {
		data[i*2] = byte(sample >> 8)
		data[i*2+1] = byte(sample)
	}
	hash := sha256.Sum256(data)
	return hash[:]
}

func ReadCompressedAudio(filePath string) ([]byte, error) {
	return os.ReadFile(filePath)
}
