package live

import (
	"context"
	"encoding/json"
	"github.com/redis/go-redis/v9"
	"notification/models"
)

type Publisher struct {
	redis  *redis.Client
	prefix string
}

func New(r *redis.Client, p string) *Publisher { return &Publisher{redis: r, prefix: p} }
func (p *Publisher) Publish(c context.Context, v *models.Notification) error {
	b, e := json.Marshal(v)
	if e != nil {
		return e
	}
	return p.redis.Publish(c, p.prefix+v.UserID.String(), b).Err()
}
