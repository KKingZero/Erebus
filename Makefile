MODULE      = github.com/KKingZero/erebus-exploit-framwork
TEAMSERVER  = ./cmd/teamserver
IMPLANT     = ./cmd/implant
BUILD_DIR   = ./build

# Implant build-time config (override via env or make args)
IMPLANT_ID     ?= $(shell head -c 16 /dev/urandom | xxd -p)
IMPLANT_SECRET ?= $(shell head -c 32 /dev/urandom | xxd -p)
CALLBACK_URL   ?= https://127.0.0.1:443
SLEEP_MS       ?= 5000
JITTER_PCT     ?= 20

LDFLAGS = -s -w \
	-X '$(MODULE)/implant.implantID=$(IMPLANT_ID)' \
	-X '$(MODULE)/implant.implantSecret=$(IMPLANT_SECRET)' \
	-X '$(MODULE)/implant.callbackURL=$(CALLBACK_URL)' \
	-X '$(MODULE)/implant.sleepMs=$(SLEEP_MS)' \
	-X '$(MODULE)/implant.jitterPct=$(JITTER_PCT)'

.PHONY: all proto teamserver implant implant-win clean

all: proto teamserver implant

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

clean:
	rm -rf $(BUILD_DIR)
	rm -f pkg/pb/*.go
