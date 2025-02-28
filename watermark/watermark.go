package watermark

import (
	"crypto"
	"crypto/rsa"
	"fmt"
	"math"
	"os"

	"github.com/Rx-11/digital-watermarking-audio/utils"
	"github.com/go-audio/audio"
	"github.com/go-audio/wav"
)

func EmbedWatermark(buffer *audio.IntBuffer, pnSequence []int) int {

	factor := int(math.Floor(float64(len(buffer.Data)) / float64(len(pnSequence))))
	for i := 0; i < len(buffer.Data) && float64(i)/float64(factor) < float64(len(pnSequence)); i += int(factor) {
		buffer.Data[i] = pnSequence[(i)/int(factor)]
	}
	SaveWatermarkedAudio(buffer)
	return len(pnSequence)
}

func SaveWatermarkedAudio(buffer *audio.IntBuffer) {
	outFile, err := os.Create("output.wav")
	if err != nil {
		panic(err)
	}
	defer outFile.Close()

	encoder := wav.NewEncoder(outFile, buffer.Format.SampleRate, buffer.SourceBitDepth, buffer.Format.NumChannels, 1)
	if err := encoder.Write(buffer); err != nil {
		panic(err)
	}
	if err := encoder.Close(); err != nil {
		panic(err)
	}
}

func ExtractWatermark(buffer *audio.IntBuffer, length int) []int {
	extractedPN := make([]int, length)
	factor := int(math.Floor(float64(len(buffer.Data)) / float64((length))))
	for i := 0; i < len(buffer.Data) && float64(i)/float64(factor) < float64(length); i += int(factor) {
		extractedPN[(i)/int(factor)] = buffer.Data[i]
	}
	for i := range extractedPN {
		if extractedPN[i] == 255 {
			extractedPN[i] = -1
		}
	}
	return extractedPN
}

func VerifyWatermark(buffer *audio.IntBuffer, extractedSignature []byte, pubKey *rsa.PublicKey) error {
	recomputedHash := utils.ComputeAudioHash(buffer)

	err := rsa.VerifyPKCS1v15(pubKey, crypto.SHA256, recomputedHash, extractedSignature)
	if err != nil {
		fmt.Println("Audio is authentic, no tampering detected")
		return nil
	} else {
		fmt.Println("WARNING: Watermark mismatch, possible tampering detected")
		return fmt.Errorf("watermark verification failed")
	}
}
