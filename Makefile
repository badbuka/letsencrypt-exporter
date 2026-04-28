.PHONY: build test vet lint fmt tidy clean all

BINARY := letsencrypt-exporter
PKG    := ./...

all: lint test build

build:
	go build -trimpath -ldflags="-s -w" -o bin/$(BINARY) .

test:
	go test -race -count=1 $(PKG)

vet:
	go vet $(PKG)

lint:
	golangci-lint run

fmt:
	golangci-lint fmt

tidy:
	go mod tidy

clean:
	rm -rf bin
