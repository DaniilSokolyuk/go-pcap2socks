# Dockerfile
FROM golang:1.21-alpine AS builder
RUN apk add --no-cache libpcap-dev gcc musl-dev
WORKDIR /app
COPY . .
RUN go build -o go-pcap2socks .

FROM alpine:latest
RUN apk add --no-cache libpcap
WORKDIR /app
COPY --from=builder /app/go-pcap2socks .
ENTRYPOINT ["./go-pcap2socks"]