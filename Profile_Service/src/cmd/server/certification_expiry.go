package main

import (
	"context"
	"time"

	"profile/pkg/closer"
	"profile/src/core/service"
	"profile/src/infrastructure/certificationexpiry"

	"go.uber.org/zap"
)

func startCertificationExpiryWorker(profileService service.CertificationService, dependencies *closer.Closer, logger *zap.Logger) {
	worker := certificationexpiry.New(profileService, time.Minute, 100, logger)
	ctx, cancel := context.WithCancel(context.Background())
	dependencies.Add("certification expiry worker", func() error {
		cancel()
		return nil
	})
	go worker.Run(ctx)
}
