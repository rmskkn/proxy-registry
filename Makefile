BINARY := registry-proxy
PKG := ./cmd/registry-proxy

.PHONY: all build run test test-race vet fmt fmt-check cve check clean

all: build

## Compile the registry-proxy binary.
build:
	go build -o $(BINARY) $(PKG)

## Build and run the proxy using config.example (override CONFIG=... as needed).
run: build
	./$(BINARY) -config $(or $(CONFIG),config.example)

## Run the test suite.
test:
	go test ./...

## Run the test suite with the race detector, matching CI/pre-commit.
test-race:
	go test ./... -race -count=1

## Run go vet.
vet:
	go vet ./...

## Check formatting without modifying files.
fmt-check:
	@unformatted="$$(gofmt -l .)"; \
	if [ -n "$$unformatted" ]; then \
		echo "gofmt needs to be run on:" >&2; \
		echo "$$unformatted" >&2; \
		exit 1; \
	fi

## Reformat all Go source files in place.
fmt:
	gofmt -w .

## Scan dependencies for known CVEs (govulncheck + osv-scanner).
cve:
	./check-cve.sh

## Run everything CI/the pre-commit hook run: CVE scan, build, vet, fmt check, race tests.
check: cve build vet fmt-check test-race

## Remove build artifacts.
clean:
	rm -f $(BINARY)
