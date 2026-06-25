MODULE      = github.com/KKingZero/erebus-exploit-framwork
TEAMSERVER  = ./cmd/teamserver
IMPLANT     = ./cmd/implant
OPERATOR    = ./cmd/operator
BUILD_DIR   = ./build

# Implant build-time config (override via env or make args)
IMPLANT_ID     ?= $(shell head -c 16 /dev/urandom | xxd -p)
IMPLANT_SECRET ?= $(shell head -c 32 /dev/urandom | xxd -p)
CALLBACK_URL   ?= https://127.0.0.1:443
SLEEP_MS       ?= 5000
JITTER_PCT     ?= 20

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

.PHONY: all proto teamserver implant implant-win implant-dll implant-shellcode implant-c operator clean

all: proto teamserver implant operator

proto:
	cd proto && bash generate.sh

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

implant-dll:
	@mkdir -p $(BUILD_DIR)
	CGO_ENABLED=1 GOOS=windows GOARCH=amd64 CC=x86_64-w64-mingw32-gcc \
		go build -buildmode=c-shared -tags dll -ldflags "$(LDFLAGS)" \
		-o $(BUILD_DIR)/implant.dll $(IMPLANT)

implant-shellcode: implant-win
	@mkdir -p $(BUILD_DIR)
	go run ./cmd/tools/pe2shellcode -i $(BUILD_DIR)/implant.exe -o $(BUILD_DIR)/implant.bin

implant-c:
	$(MAKE) -C cimplant all \
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
