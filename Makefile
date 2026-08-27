.PHONY: fmt vet test race build release-check snapshot clean

fmt:
	go fmt ./...

vet:
	go vet ./...

test:
	go test ./...

race:
	go test -race ./...

build:
	mkdir -p bin
	go build -trimpath -o bin/nordmac ./cmd/nordmac

release-check:
	goreleaser check

snapshot:
	goreleaser release --snapshot --clean

clean:
	rm -f bin/nordmac coverage.out
	rm -rf dist

