# TODO

## Ticket / Brigade access

- After Brigade Service is implemented, add a reliable `user_id -> brigade_id` lookup and pass/resolve `actor_brigade_id` for ticket operations.
- Allow brigade users to change/complete only tickets assigned to their own brigade:
  `ticket.brigade_id != nil && ticket.brigade_id == actor_brigade_id`.
- Keep `admin` and `dispatcher` as privileged roles for cross-brigade ticket management.

## Ticket attachments

- Add ticket file attachments after the base ticket flow and Brigade Service access rules are stable.
- Store binary files in S3-compatible storage, such as MinIO for local/dev and S3/Object Storage in production.
- Store only attachment metadata in Postgres, for example `ticket_id`, `uploaded_by`, `file_name`, `content_type`, `size_bytes`, `object_key`, `checksum`, `status`, timestamps.
- Prefer presigned upload/download URLs so files do not pass through API Gateway or gRPC services.
- Attachment access must inherit ticket access: users can upload/download only when they are allowed to access the related ticket.
