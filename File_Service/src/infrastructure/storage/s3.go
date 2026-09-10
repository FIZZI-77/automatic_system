package storage

import (
	"context"
	"fmt"
	"net/url"
	"time"

	"file/pkg/telemetry"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
)

type Config struct {
	Endpoint       string
	PublicEndpoint string
	Region         string
	AccessKey      string
	SecretKey      string
	Bucket         string
	UsePathStyle   bool
}

type S3 struct {
	client  *s3.Client
	presign *s3.PresignClient
	bucket  string
}

func New(cfg Config) *S3 {
	options := s3.Options{
		Region:       cfg.Region,
		Credentials:  credentials.NewStaticCredentialsProvider(cfg.AccessKey, cfg.SecretKey, ""),
		BaseEndpoint: aws.String(cfg.Endpoint),
		UsePathStyle: cfg.UsePathStyle,
	}
	client := s3.New(options)
	if cfg.PublicEndpoint != "" {
		options.BaseEndpoint = aws.String(cfg.PublicEndpoint)
	}
	presignClient := s3.New(options)
	return &S3{
		client:  client,
		presign: s3.NewPresignClient(presignClient),
		bucket:  cfg.Bucket,
	}
}

func (s *S3) EnsureBucket(ctx context.Context) error {
	ctx, span := s.startSpan(ctx, "S3.EnsureBucket")
	defer span.End()

	_, err := s.client.HeadBucket(ctx, &s3.HeadBucketInput{Bucket: &s.bucket})
	if err == nil {
		return nil
	}
	_, err = s.client.CreateBucket(ctx, &s3.CreateBucketInput{Bucket: &s.bucket})
	recordError(span, err)
	return err
}

func (s *S3) UploadURL(ctx context.Context, key, contentType, checksum string, ttl time.Duration) (string, error) {
	ctx, span := s.startSpan(ctx, "S3.PresignPutObject")
	defer span.End()

	in := &s3.PutObjectInput{
		Bucket:      &s.bucket,
		Key:         &key,
		ContentType: &contentType,
	}
	if checksum != "" {
		in.ChecksumSHA256 = &checksum
	}
	res, err := s.presign.PresignPutObject(ctx, in, s3.WithPresignExpires(ttl))
	if err != nil {
		recordError(span, err)
		return "", err
	}
	return res.URL, nil
}

func (s *S3) DownloadURL(ctx context.Context, key, name string, ttl time.Duration) (string, error) {
	ctx, span := s.startSpan(ctx, "S3.PresignGetObject")
	defer span.End()

	disposition := fmt.Sprintf(`attachment; filename*=UTF-8''%s`, url.PathEscape(name))
	input := &s3.GetObjectInput{
		Bucket:                     &s.bucket,
		Key:                        &key,
		ResponseContentDisposition: &disposition,
	}
	res, err := s.presign.PresignGetObject(ctx, input, s3.WithPresignExpires(ttl))
	if err != nil {
		recordError(span, err)
		return "", err
	}
	return res.URL, nil
}

func (s *S3) Stat(ctx context.Context, key string) (int64, string, error) {
	ctx, span := s.startSpan(ctx, "S3.HeadObject")
	defer span.End()

	res, err := s.client.HeadObject(ctx, &s3.HeadObjectInput{Bucket: &s.bucket, Key: &key})
	if err != nil {
		recordError(span, err)
		return 0, "", err
	}
	return aws.ToInt64(res.ContentLength), aws.ToString(res.ContentType), nil
}

func (s *S3) Delete(ctx context.Context, key string) error {
	ctx, span := s.startSpan(ctx, "S3.DeleteObject")
	defer span.End()

	_, err := s.client.DeleteObject(ctx, &s3.DeleteObjectInput{Bucket: &s.bucket, Key: &key})
	recordError(span, err)
	return err
}

func (s *S3) Move(ctx context.Context, source, target string) error {
	ctx, span := s.startSpan(ctx, "S3.MoveObject")
	defer span.End()

	copySource := url.PathEscape(s.bucket + "/" + source)
	if _, err := s.client.CopyObject(ctx, &s3.CopyObjectInput{Bucket: &s.bucket, Key: &target, CopySource: &copySource}); err != nil {
		recordError(span, err)
		return err
	}
	if err := s.Delete(ctx, source); err != nil {
		_ = s.Delete(ctx, target)
		recordError(span, err)
		return err
	}
	return nil
}

func (s *S3) startSpan(ctx context.Context, operation string) (context.Context, trace.Span) {
	return telemetry.Tracer("file/storage").Start(
		ctx,
		operation,
		trace.WithSpanKind(trace.SpanKindClient),
		trace.WithAttributes(
			attribute.String("rpc.system", "aws-api"),
			attribute.String("rpc.service", "s3"),
			attribute.String("s3.bucket.name", s.bucket),
		),
	)
}

func recordError(span trace.Span, err error) {
	if err == nil {
		return
	}
	span.RecordError(err)
	span.SetStatus(codes.Error, err.Error())
}
