build:
	@go build -o bin/cercle main.go

run: build
	@./bin/cercle

test:
	@go test -v ./...

format:
	@go fmt ./...

pride:
	@find . -name '*.go' | xargs wc -l