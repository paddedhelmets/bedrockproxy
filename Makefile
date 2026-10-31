.PHONY: all bedrockproxy bedping lanprobe vet test dist clean

TARGETS := linux/amd64 linux/arm64 linux/armv7 darwin/amd64 darwin/arm64 windows/amd64
LDFLAGS := -s -w

all: bedrockproxy bedping lanprobe

bedrockproxy:
	CGO_ENABLED=0 go build -trimpath -ldflags="$(LDFLAGS)" -o bedrockproxy .

bedping:
	CGO_ENABLED=0 go build -trimpath -ldflags="$(LDFLAGS)" -o bedping ./cmd/bedping

lanprobe:
	CGO_ENABLED=0 go build -trimpath -ldflags="$(LDFLAGS)" -o lanprobe ./cmd/lanprobe

vet:
	go vet ./...

test:
	go test ./...

# dist builds static, stripped, cross-compiled binaries into dist/.
# linux/armv7 targets ARMv7 hard-float (Raspberry Pi 2 + other armv7 SBCs):
# GOARCH=arm GOARM=7.
dist:
	@rm -rf dist
	@for t in $(TARGETS); do \
	  goos=$${t%/*}; rest=$${t#*/}; \
	  if [ "$${rest}" = armv7 ]; then goarch=arm; goarm=7; else goarch=$${rest}; goarm=; fi; \
	  ext=""; [ $$goos = windows ] && ext=".exe"; \
	  printf "  building %-18s\n" "$$goos/$${rest}"; \
	  GOOS=$$goos GOARCH=$$goarch GOARM=$$goarm CGO_ENABLED=0 go build -trimpath -ldflags="$(LDFLAGS)" \
	    -o "dist/bedrockproxy-$${goos}-$${rest}$${ext}" .; \
	  GOOS=$$goos GOARCH=$$goarch GOARM=$$goarm CGO_ENABLED=0 go build -trimpath -ldflags="$(LDFLAGS)" \
	    -o "dist/bedping-$${goos}-$${rest}$${ext}" ./cmd/bedping; \
	  GOOS=$$goos GOARCH=$$goarch GOARM=$$goarm CGO_ENABLED=0 go build -trimpath -ldflags="$(LDFLAGS)" \
	    -o "dist/lanprobe-$${goos}-$${rest}$${ext}" ./cmd/lanprobe; \
	done
	@echo "--- dist/ ---" && ls -la dist

clean:
	rm -f bedrockproxy bedping
	rm -rf dist
