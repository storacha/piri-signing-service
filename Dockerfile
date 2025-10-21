FROM golang:1.24-bookworm AS build

WORKDIR /signer

COPY go.* .
RUN go mod download
COPY . .

ARG VERSION
ARG DATE

RUN CGO_ENABLED=0 GOOS=linux GOARCH=arm64 \
    go build -ldflags="-w -s" -o signer github.com/storacha/piri-signing-service

FROM scratch
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=build /signer/signer /usr/bin/

EXPOSE 8080

ENTRYPOINT ["/usr/bin/signer"]
CMD ["--port", "8080"]
