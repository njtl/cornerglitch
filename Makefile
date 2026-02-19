.PHONY: build run clean vet

build:
	go build -o glitch ./cmd/glitch

run: build
	./glitch

vet:
	go vet ./...

clean:
	rm -f glitch
