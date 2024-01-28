# build
FROM golang:1.21-alpine AS builder

WORKDIR /app

COPY . .

RUN go build -o main ./cmd/main.go

# Run
FROM gcr.io/distroless/static-debian12

WORKDIR /app
COPY --from=builder /app/main .

EXPOSE 8080

CMD ["/app/main"]