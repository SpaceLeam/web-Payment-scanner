.PHONY: build run test clean install-deps check-version help

# Check Go version (requires Go 1.22+)
check-version:
	@echo "🔍 Checking Go version..."
	@go version | grep -q "go1.22\|go1.23\|go1.24\|go1.25" || (echo "⚠️  Go 1.22+ required" && exit 1)
	@echo "✅ Go version OK"

# Install all dependencies
install-deps: check-version
	@echo "📦 Installing Go dependencies..."
	@go get github.com/playwright-community/playwright-go@v0.5200.1
	@go get github.com/spf13/cobra@v1.10.1
	@go get github.com/spf13/pflag@v1.0.9
	@go get github.com/fatih/color@v1.18.0
	@go get github.com/olekukonko/tablewriter@v1.1.1
	@go get github.com/schollz/progressbar/v3@v3.14.1
	@go get golang.org/x/sync@v0.8.0
	@go mod tidy
	@echo "🌐 Installing Playwright browsers (Firefox)..."
	@go run github.com/playwright-community/playwright-go/cmd/playwright@latest install firefox
	@echo "✅ All dependencies installed"

# Build the scanner binary
build: check-version
	@echo "🔨 Building scanner..."
	@mkdir -p bin
	@go build -ldflags="-s -w" -o bin/scanner cmd/scanner/main.go
	@echo "✅ Build complete: bin/scanner"

# Run scanner directly (no build)
run:
	@go run cmd/scanner/main.go

# Run tests with coverage
test:
	@echo "🧪 Running tests..."
	@go test ./... -v -cover -coverprofile=coverage.txt
	@echo "✅ Tests complete"

# Run tests with race detection
test-race:
	@echo "🧪 Running tests with race detection..."
	@go test ./... -race -v
	@echo "✅ Race tests complete"

# Clean build artifacts
clean:
	@rm -rf bin/ reports/ .ms-playwright/ coverage.txt
	@echo "🧹 Cleaned build artifacts"

# Format code
fmt:
	@echo "📝 Formatting code..."
	@go fmt ./...
	@echo "✅ Code formatted"

# Run linter (if golangci-lint installed)
lint:
	@echo "🔍 Running linter..."
	@golangci-lint run || echo "⚠️  golangci-lint not installed, skipping..."

# Install the scanner to GOPATH/bin
install: build
	@echo "📦 Installing scanner to GOPATH/bin..."
	@go install cmd/scanner/main.go
	@echo "✅ Scanner installed"

# Show help
help:
	@echo "Payment Security Scanner - Makefile Commands"
	@echo ""
	@echo "Available commands:"
	@echo "  make check-version    - Check Go version (requires 1.22+)"
	@echo "  make install-deps     - Install all dependencies (Go + Playwright)"
	@echo "  make build            - Build scanner binary to bin/scanner"
	@echo "  make run              - Run scanner directly without building"
	@echo "  make test             - Run tests with coverage"
	@echo "  make test-race        - Run tests with race detection"
	@echo "  make clean            - Clean build artifacts and reports"
	@echo "  make fmt              - Format code with go fmt"
	@echo "  make lint             - Run linter (requires golangci-lint)"
	@echo "  make install          - Install scanner to GOPATH/bin"
	@echo "  make help             - Show this help message"
