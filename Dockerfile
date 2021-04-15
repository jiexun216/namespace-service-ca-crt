FROM alpine:latest

ADD namespace-service-ca-crt /namespace-service-ca-crt
ENTRYPOINT ["./namespace-service-ca-crt"]