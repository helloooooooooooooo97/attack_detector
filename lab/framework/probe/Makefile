BIN := behinder-probe

.PHONY: all darwin linux-amd64 linux-arm64 clean replay-test

all: darwin linux-amd64 linux-arm64

darwin:
	CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o $(BIN)-darwin .

linux-amd64:
	GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o $(BIN)-linux-amd64 .

linux-arm64:
	GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o $(BIN)-linux-arm64 .

# Validate detection logic against the lab captures
replay-test: linux-amd64
	./$(BIN)-linux-amd64 -r ../data/captures/cap_close.pcap -json -ja3=false | grep -c behinder.mem_shell_flow || true
	./$(BIN)-linux-amd64 -r ../data/captures/cap_keepalive.pcap -json -ja3=false | grep -c behinder.file_webshell_flow || true
	./$(BIN)-linux-amd64 -r ../data/captures/cap_normal.pcap -json -ja3=false | grep -c DETECTED || true

clean:
	rm -f $(BIN)-darwin $(BIN)-linux-amd64 $(BIN)-linux-arm64
