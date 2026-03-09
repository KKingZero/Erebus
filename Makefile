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

LDFLAGS = -s -w \
	-X '$(MODULE)/implant.implantID=$(IMPLANT_ID)' \
	-X '$(MODULE)/implant.implantSecret=$(IMPLANT_SECRET)' \
	-X '$(MODULE)/implant.callbackURL=$(CALLBACK_URL)' \
	-X '$(MODULE)/implant.sleepMs=$(SLEEP_MS)' \
	-X '$(MODULE)/implant.jitterPct=$(JITTER_PCT)' \
	-X '$(MODULE)/implant.caCertPEM=$(CA_CERT_PEM)' \
	-X '$(MODULE)/implant.transportType=$(TRANSPORT_TYPE)' \
	-X '$(MODULE)/implant.dnsDomain=$(DNS_DOMAIN)' \
	-X '$(MODULE)/implant.dnsServer=$(DNS_SERVER)'

.PHONY: all proto teamserver implant implant-win operator clean

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

clean:
	rm -rf $(BUILD_DIR)
	rm -f pkg/pb/*.go
