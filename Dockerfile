# syntax=docker/dockerfile:1
FROM golang:1.26.2-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" \
    -o /out/letsencrypt-exporter ./cmd/letsencrypt-exporter

FROM gcr.io/distroless/static:nonroot
USER nonroot:nonroot
COPY --from=build /out/letsencrypt-exporter /letsencrypt-exporter
EXPOSE 8622
ENTRYPOINT ["/letsencrypt-exporter"]
