package pkg

import (
	"auth/pkg/telemetry"
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"github.com/jackc/pgx/v5/pgxpool"
	"os"
)

type Config struct {
	Host     string
	Port     string
	Username string
	Password string
	DbName   string
	SSLMode  string
}

func NewPostgresDB(cfg Config) (*pgxpool.Pool, error) {
	connString := fmt.Sprintf("host=%s port=%s user=%s dbname=%s password=%s sslmode=%s",
		cfg.Host, cfg.Port, cfg.Username, cfg.DbName, cfg.Password, cfg.SSLMode)
	db, err := telemetry.NewPostgresPool(context.Background(), connString)

	if err != nil {
		return nil, err
	}

	if err = db.Ping(context.Background()); err != nil {
		db.Close()
		return nil, err
	}
	return db, nil
}

func LoadRSAPrivateKey(path string) (*rsa.PrivateKey, error) {
	keyBytes, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("load rsa private key: read file: %w", err)
	}

	block, _ := pem.Decode(keyBytes)
	if block == nil {
		return nil, fmt.Errorf("load rsa private key: failed to decode PEM block")
	}

	privateKeyAny, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err == nil {
		privateKey, ok := privateKeyAny.(*rsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("load rsa private key: parsed key is not RSA")
		}
		return privateKey, nil
	}

	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("load rsa private key: parse key: %w", err)
	}

	return privateKey, nil
}
