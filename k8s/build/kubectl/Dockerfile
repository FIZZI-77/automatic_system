FROM registry.k8s.io/kubectl:v1.33.4 AS kubectl

FROM alpine:3.22

COPY --from=kubectl /bin/kubectl /usr/local/bin/kubectl

ENTRYPOINT ["kubectl"]
