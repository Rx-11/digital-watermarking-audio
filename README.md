# Digital Audio Watermarking with RSA Signatures 

A robust digital audio watermarking system using RSA cryptography and PN sequences for embedding and verifying unique signatures within WAV files.

## Features

✅ Generate RSA key pairs for signing and verification.  
✅ Embed a unique digital signature as an imperceptible watermark in the audio file.  
✅ Extract and verify the watermark to ensure authenticity.  
✅ Robust against minor audio alterations while maintaining integrity.  

## 🚀 Getting Started

### 1️⃣ Install Dependencies

Make sure you have the following installed:

#### Install FFmpeg (Required)

**Linux (Ubuntu/Debian)**
```sh
sudo apt install ffmpeg
```

**MacOS**
```sh
brew install ffmpeg
```

**Windows**  
Download and install from [FFmpeg official website](https://ffmpeg.org/download.html).

#### Install Go Modules

Run the following inside your project directory:

```sh
go mod tidy
```

## 2️⃣ How It Works

### Convert Audio Format

The WAV file is converted to the required format (Only done due to the limitations of the go-audio package):

```go
cmd := exec.Command("ffmpeg", "-y", "-i", inputFile,
    "-ac", "1", "-ar", "8000", "-acodec", "pcm_s16le", outputFile)
cmd.Stdout = os.Stdout
cmd.Stderr = os.Stderr
err := cmd.Run()
if err != nil {
    log.Fatalf("FFmpeg conversion failed: %v", err)
}
```

### Generate RSA Keys

```go
privKey, pubKey := utils.GenerateKeys()
```

### Sign the Audio Metadata

```go
signature, err := utils.SignMessage([]byte("Unique watermark metadata"), privKey)
if err != nil {
    log.Fatal(err)
}
```

### Convert Signature to PN Sequence

```go
pn := utils.SignatureToPN(signature)
```

### Embed Watermark in Audio

```go
length := watermark.EmbedWatermark(buffer, pn)
```

### Extract & Verify Watermark

```go
extractedPN := watermark.ExtractWatermark(buffer, length)
extractedSignature := utils.PNToSignature(extractedPN)

if err := utils.VerifySignature([]byte("Unique watermark metadata"), extractedSignature, pubKey); err != nil {
    log.Fatal("Watermark verification failed!")
} else {
    fmt.Println("Successfully verified audio watermark!")
}
```

## 🛠 Project Structure

```
📂 digital-audio-watermarking
│── main.go                     # Main entry point
│── utils/
│   ├── utils.go                 # Key generation, signing, verification
│── watermark/
│   ├── watermark.go             # Embedding and extraction logic
│── go.mod                       # Go module dependencies
│── README.md                    # This file!
```

## 🎯 How to Run

1️⃣ Place a WAV file (`input.wav`) in the project folder.  
2️⃣ Run the watermarking process:

```sh
go run main.go
```

3️⃣ The output file (`output.wav`) will contain an embedded watermark.  
4️⃣ The program will extract and verify the watermark.  

## 📜 License

This project is licensed under the MIT License.

## 🤝 Contributions

Feel free to open issues or submit pull requests to improve this project! 🚀

🔹 Developed with ❤️ in Golang 🔹

