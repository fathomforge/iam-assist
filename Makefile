.PHONY: build test lint clean install

BINARY := iam-assist
VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
LDFLAGS := -ldflags "-X main.version=$(VERSION)"

build:
	go build $(LDFLAGS) -o $(BINARY) .

install:
	go install $(LDFLAGS) .

test:
	go test -race -cover ./...

lint:
	golangci-lint run ./...

clean:
	rm -f $(BINARY)

# Quick smoke test
smoke: build
	echo 'Read BigQuery data in project my-proj' | ./$(BINARY) generate --json -
