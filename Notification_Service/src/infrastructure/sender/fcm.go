package sender

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"golang.org/x/oauth2/google"
	"io"
	"net/http"
	"notification/models"
	"os"
	"strings"
)

type FCM struct {
	project string
	client  *http.Client
}

func NewFCM(ctx context.Context, path string) (*FCM, error) {
	raw, e := os.ReadFile(path)
	if e != nil {
		return nil, e
	}
	var meta struct {
		ProjectID string `json:"project_id"`
	}
	if e = json.Unmarshal(raw, &meta); e != nil {
		return nil, e
	}
	cfg, e := google.JWTConfigFromJSON(raw, "https://www.googleapis.com/auth/firebase.messaging")
	if e != nil {
		return nil, e
	}
	return &FCM{project: meta.ProjectID, client: cfg.Client(ctx)}, nil
}
func (f *FCM) Send(ctx context.Context, d *models.Delivery, n *models.Notification) (string, error) {
	payload := map[string]any{"message": map[string]any{"token": d.Recipient, "notification": map[string]string{"title": n.Title, "body": n.Body}, "data": n.Data}}
	raw, _ := json.Marshal(payload)
	req, e := http.NewRequestWithContext(ctx, http.MethodPost, "https://fcm.googleapis.com/v1/projects/"+f.project+"/messages:send", bytes.NewReader(raw))
	if e != nil {
		return "", e
	}
	req.Header.Set("Content-Type", "application/json")
	res, e := f.client.Do(req)
	if e != nil {
		return "", e
	}
	defer res.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(res.Body, 1<<20))
	if res.StatusCode/100 != 2 {
		err := fmt.Errorf("FCM %s: %s", res.Status, string(body))
		if res.StatusCode == 404 || strings.Contains(string(body), "UNREGISTERED") || strings.Contains(string(body), "INVALID_ARGUMENT") {
			return "", fmt.Errorf("%w: %v", ErrPermanent, err)
		}
		return "", err
	}
	var out struct {
		Name string `json:"name"`
	}
	_ = json.Unmarshal(body, &out)
	return out.Name, nil
}
