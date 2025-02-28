package main

import (
	// "encoding/base64"
	// "fmt"

	"fmt"
	"log"
	"os/exec"

	"github.com/Rx-11/digital-watermarking-audio/utils"
	"github.com/Rx-11/digital-watermarking-audio/watermark"
)

func main() {

	inputFile := "input.wav"
	outputFile := "output1.wav"

	cmd := exec.Command("ffmpeg", "-y", "-i", inputFile,
		"-ac", "1",
		"-ar", "8000",
		"-acodec", "pcm_s16le",
		outputFile)

	// cmd.Stdout = os.Stdout
	// cmd.Stderr = os.Stderr

	err := cmd.Run()
	if err != nil {
		fmt.Println("Error executing FFmpeg:", err)
		return
	}

	fmt.Println("Conversion completed:", outputFile)

	buffer, err := utils.LoadWavFile("output1.wav")
	if err != nil {
		log.Fatal(err)
	}
	watermark.SaveWatermarkedAudio(buffer)
	message := []byte("Unique watermark metadata or audio hash")
	privKey, pubKey := utils.GenerateKeys()
	signature, err := utils.SignMessage(message, privKey)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("Public Key:", pubKey)

	pn := utils.SignatureToPN(signature)
	length := watermark.EmbedWatermark(buffer, pn)
	fmt.Println("embedded watermark in audio and saved the output wav file")
	buffer, err = utils.LoadWavFile("output.wav")
	if err != nil {
		log.Fatal(err)
	}
	pn = watermark.ExtractWatermark(buffer, length)
	signature = utils.PNToSignature(pn)
	err = utils.VerifySignature(message, signature, pubKey)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("Successfully verified audio")

}
