FROM golang:1.22-alpine AS build

WORKDIR /app
COPY go.mod ./
COPY go.sum ./
COPY cmd ./cmd
COPY internal ./internal

RUN CGO_ENABLED=0 GOOS=linux go build -o /bin/api ./cmd/api

FROM alpine:3.20

RUN adduser -D -H appuser
USER appuser

COPY --from=build /bin/api /api

EXPOSE 8080
ENTRYPOINT ["/api"]
