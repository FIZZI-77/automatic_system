package main

import (
	"context"
	"fmt"
	"log"
	"os"

	"github.com/google/uuid"

	"notification/models"
	"notification/src/infrastructure/sender"
)

func main() {
	if len(os.Args) < 2 {
		log.Fatal("usage: fcm-test <registration-token>")
	}

	token := os.Args[1]

	credentials := os.Getenv("FCM_SERVICE_ACCOUNT_FILE")
	if credentials == "" {
		log.Fatal("FCM_SERVICE_ACCOUNT_FILE is empty")
	}

	ctx := context.Background()

	client, err := sender.NewFCM(ctx, credentials)
	if err != nil {
		log.Fatalf("initialize FCM: %v", err)
	}

	delivery := &models.Delivery{
		ID:        uuid.New(),
		Recipient: token,
		Channel:   "PUSH",
	}

	notification := &models.Notification{
		ID:        uuid.New(),
		UserID:    uuid.New(),
		EventType: "fcm.test",
		Title:     "FCM test",
		Body:      "Push из Automatic City Services",
		Data: map[string]string{
			"type": "test",
		},
	}

	providerID, err := client.Send(
		ctx,
		delivery,
		notification,
	)
	if err != nil {
		log.Fatalf("send FCM: %v", err)
	}

	fmt.Println("FCM SENT")
	fmt.Println("provider:", providerID)
}
