FROM golang:1.25 AS builder
WORKDIR /app

COPY . .
RUN CGO_ENABLED=0 GOOS=linux  go build -o /app/rp-demo ./main.go

FROM alpine
WORKDIR /app
COPY --from=builder /app/rp-demo /app/rp-demo
EXPOSE 8091
ENTRYPOINT ["/app/rp-demo"]