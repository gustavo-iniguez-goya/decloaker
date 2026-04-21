
prepare:
	@mkdir -p bin/
	go mod tidy

ebpf:
	@cd pkg/ebpf/kern/ && make

decloaker:
	CGO_ENABLED=0 go build -o bin/decloaker

all: prepare ebpf decloaker

clean:
	rm -f bin/decloaker
	@cd pkg/ebpf/kern && make clean

.DEFAULT_GOAL := all
