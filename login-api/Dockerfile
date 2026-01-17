FROM golang:1.25 AS builder
WORKDIR /app

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -o /app/login-api ./main.go

FROM alpine
WORKDIR /app
COPY --from=builder /app/login-api /app/login-api
EXPOSE 8090
ENTRYPOINT ["/app/login-api"]
