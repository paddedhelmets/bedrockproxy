.PHONY: all bedrockproxy bedping vet test dist clean

TARGETS := linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 windows/amd64
LDFLAGS := -s -w

all: bedrockproxy bedping

bedrockproxy:
	CGO_ENABLED=0 go build -trimpath -ldflags="$(LDFLAGS)" -o bedrockproxy .

bedping:
	CGO_ENABLED=0 go build -trimpath -ldflags="$(LDFLAGS)" -o bedping ./cmd/bedping

vet:
	go vet ./...

test:
	go test ./...

# dist builds static, stripped, cross-compiled binaries into dist/.
dist:
	@rm -rf dist
	@for t in $(TARGETS); do \
	  goos=$${t%/*}; goarch=$${t#*/}; ext=""; \
	  [ $$goos = windows ] && ext=".exe"; \
	  printf "  building %-16s\n" "$$goos/$$goarch"; \
	  GOOS=$$goos GOARCH=$$goarch CGO_ENABLED=0 go build -trimpath -ldflags="$(LDFLAGS)" \
	    -o "dist/bedrockproxy-$${goos}-$${goarch}$${ext}" .; \
	  GOOS=$$goos GOARCH=$$goarch CGO_ENABLED=0 go build -trimpath -ldflags="$(LDFLAGS)" \
	    -o "dist/bedping-$${goos}-$${goarch}$${ext}" ./cmd/bedping; \
	done
	@echo "--- dist/ ---" && ls -la dist

clean:
	rm -f bedrockproxy bedping
	rm -rf dist
