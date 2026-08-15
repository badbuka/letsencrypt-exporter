# syntax=docker/dockerfile:1
FROM golang:1.27rc2-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" \
    -o /out/letsencrypt-exporter .

# Stock certbot installs /etc/letsencrypt/{live,archive} with mode 0700 root:root.
# cert.pem under live/ is a relative symlink into archive/, so the exporter needs
# read+execute on both directories. The simplest deployment is therefore to run
# the container as root; operators who tighten certbot perms or use a dedicated
# group can override with `docker run --user 65532:65532` etc.
FROM gcr.io/distroless/static-debian12:latest
COPY --from=build /out/letsencrypt-exporter /letsencrypt-exporter
EXPOSE 8622
ENTRYPOINT ["/letsencrypt-exporter"]
