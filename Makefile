BINARY_NAME=certscan
CMD_DIR=./cmd

all: build

init:
	go mod init certscan_webhook
	go mod tidy

build:
	go build -o $(BINARY_NAME) $(CMD_DIR)

run: build
	./$(BINARY_NAME)

clean:
	rm -f $(BINARY_NAME)

rebuild: clean build
