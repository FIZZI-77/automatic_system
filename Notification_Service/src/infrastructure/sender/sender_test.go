package sender

import (
	"context"
	"net"
	"testing"
	"time"

	"notification/models"
)

func TestEmailSendHonorsContextDeadline(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	accepted := make(chan net.Conn, 1)
	go func() {
		conn, acceptErr := listener.Accept()
		if acceptErr == nil {
			accepted <- conn
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	started := time.Now()
	_, err = NewEmail(listener.Addr().String(), "sender@example.com", "", "").Send(ctx,
		&models.Delivery{Recipient: "recipient@example.com"},
		&models.Notification{Title: "subject", Body: "body"},
	)
	if err == nil {
		t.Fatal("expected stalled SMTP server to time out")
	}
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("SMTP deadline was not honored: %v", elapsed)
	}
	select {
	case conn := <-accepted:
		_ = conn.Close()
	default:
	}
}
