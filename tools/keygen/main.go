package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func main() {
	outputDir := flag.String("out", "keys", "output directory")
	flag.Parse()

	if strings.EqualFold(filepath.Ext(*outputDir), ".pem") {
		panic(fmt.Errorf("-out expects a directory, not a PEM file path: %s", *outputDir))
	}
	if info, err := os.Stat(*outputDir); err == nil && !info.IsDir() {
		panic(fmt.Errorf("-out path exists and is not a directory: %s", *outputDir))
	} else if err != nil && !os.IsNotExist(err) {
		panic(err)
	}
	if err := os.MkdirAll(*outputDir, 0o755); err != nil {
		panic(err)
	}
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
	privateDER, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		panic(err)
	}
	publicDER, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		panic(err)
	}
	if err = writePEM(filepath.Join(*outputDir, "private.pem"), "PRIVATE KEY", privateDER, 0o600); err != nil {
		panic(err)
	}
	if err = writePEM(filepath.Join(*outputDir, "public.pem"), "PUBLIC KEY", publicDER, 0o644); err != nil {
		panic(err)
	}
	fmt.Printf("generated JWT key pair in %s\n", *outputDir)
}

func writePEM(path, blockType string, data []byte, mode os.FileMode) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, mode)
	if err != nil {
		return err
	}
	defer file.Close()
	return pem.Encode(file, &pem.Block{Type: blockType, Bytes: data})
}
