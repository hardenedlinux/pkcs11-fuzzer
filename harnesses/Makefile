# harnesses/Makefile
#
# Builds all libFuzzer harnesses against the libfuzzer sanitizer tree.
# Requires the build tree to be present (run build-scripts/build-all.sh first).
#
# Usage:
#   make              # build all harnesses
#   make clean        # remove harness binaries
#   make smoke-test   # run each harness for 10 seconds with corpus seeds

PROJECT_ROOT := $(abspath $(dir $(lastword $(MAKEFILE_LIST)))..)
BUILDS       := $(PROJECT_ROOT)/builds
LIBFUZZER    := $(BUILDS)/libfuzzer
TOKEN_TMPL   := $(PROJECT_ROOT)/token-template

# System Clang is the compiler.  The unversioned alias (managed by
# update-alternatives) is used here; override with CC=clang-18 if needed.
CC  := clang
CXX := clang++

# ---------------------------------------------------------------------------
# Compiler flags for the libfuzzer sanitizer tree
#
# -fsanitize=fuzzer        provides libFuzzer's main() and mutation engine.
#                          Clang resolves libclang_rt.fuzzer-x86_64.a from
#                          its own resource directory automatically — no
#                          manual library path required.
# -fno-sanitize=vptr       avoids false positives on void* function pointers
#                          across dlopen boundaries (PKCS#11 C ABI).
# -fno-sanitize=function   suppresses Clang-specific false positives from
#                          intentional C-style casts in OpenSSL and SoftHSM2.
# -fuse-ld=lld             use LLVM's lld; consistent with how the target
#                          libraries were linked.
# ---------------------------------------------------------------------------
SAN_FLAGS    := -fsanitize=fuzzer,address,undefined \
                -fno-sanitize=vptr,function \
                -fno-sanitize-recover=undefined \
                -fno-omit-frame-pointer -g -O1

LINK_FLAGS   := $(SAN_FLAGS) \
                -fuse-ld=lld \
                -rdynamic \
                -Wl,-rpath,$(LIBFUZZER)/lib/softhsm

# ---------------------------------------------------------------------------
# Include / library paths (all from the libfuzzer tree)
# ---------------------------------------------------------------------------
PKCS11_INC   := $(LIBFUZZER)/include \
                $(PROJECT_ROOT)/src/softhsm2/src/lib/pkcs11 \
                $(PROJECT_ROOT)/src/libp11/src
OPENSSL_INC  := $(LIBFUZZER)/include
OPENSSL_LIBS := $(LIBFUZZER)/lib/libssl.a $(LIBFUZZER)/lib/libcrypto.a

# Preprocessor definitions injected into every harness
DEFS         := -DHARNESS_PROJECT_ROOT='"$(PROJECT_ROOT)"' \
                -DSOFTHSM2_MODULE_PATH='"$(LIBFUZZER)/lib/softhsm/libsofthsm2.so"' \
                -DENGINE_PATH='"$(LIBFUZZER)/lib/engines-3/pkcs11.so"' \
                -DOPENSC_PKCS11_PATH='"$(LIBFUZZER)/lib/opensc-pkcs11.so"'

CFLAGS_ALL   := $(SAN_FLAGS) \
                $(addprefix -I,$(PKCS11_INC)) \
                -I$(OPENSSL_INC) \
                -I. \
                $(DEFS) \
                -Wall -Wextra -Wno-unused-parameter

# libFuzzer dictionary: injects PKCS#11 constants (CKM_*, CKA_*, CKO_*) into
# mutations, accelerating discovery of mechanism dispatch and attribute paths.
DICT := $(PROJECT_ROOT)/harnesses/pkcs11.dict

# ---------------------------------------------------------------------------
# Harness targets
# ---------------------------------------------------------------------------
PKCS11_HARNESSES := \
    pkcs11_sign_fuzz \
    pkcs11_decrypt_fuzz \
    pkcs11_findobj_fuzz \
    pkcs11_createobj_fuzz \
    pkcs11_session_fuzz \
    pkcs11_state_machine_fuzz \
    pkcs11_concurrency_fuzz \
    pkcs11_token_reset_fuzz \
    pkcs11_wrap_fuzz \
    pkcs11_attrs_fuzz \
    pkcs11_digest_fuzz \
    pkcs11_multipart_fuzz \
    pkcs11_keygen_fuzz \
    pkcs11_encrypt_fuzz \
    pkcs11_verify_fuzz \
    pkcs11_random_fuzz \
    pkcs11_hmac_fuzz

TLS_HARNESS    := tls_pkcs11_fuzz
LIBP11_HARNESS := libp11_evp_fuzz
OPENSC_HARNESS := opensc_pkcs11_fuzz

ALL_TARGETS := $(PKCS11_HARNESSES) $(TLS_HARNESS) $(LIBP11_HARNESS) $(OPENSC_HARNESS)

.PHONY: all clean smoke-test

all: $(ALL_TARGETS)
	@echo ""
	@echo "Built harnesses:"
	@ls -lh $(ALL_TARGETS) 2>/dev/null

# ---------------------------------------------------------------------------
# PKCS#11 harnesses: C-only, link libsofthsm2.so at runtime via dlopen
# ---------------------------------------------------------------------------
$(PKCS11_HARNESSES): % : %.c common.h
	$(CC) $(CFLAGS_ALL) $< \
		$(LINK_FLAGS) \
		-ldl -lpthread \
		-o $@

# ---------------------------------------------------------------------------
# TLS harness: links OpenSSL statically (for ENGINE / TLS APIs).
# Compiled with CC (not CXX) — the harness is pure C, and using clang++
# would apply C++ name mangling to LLVMFuzzerTestOneInput, making it
# invisible to the C-ABI symbol that libFuzzer.a expects.
# The ENGINE API is deprecated in OpenSSL 3.x but still present with
# enable-deprecated; suppress the warnings since this is intentional usage.
# ---------------------------------------------------------------------------
$(TLS_HARNESS): tls_pkcs11_fuzz.c common.h
	$(CC) $(CFLAGS_ALL) -Wno-deprecated-declarations $< \
		$(LINK_FLAGS) \
		-Wl,--whole-archive $(OPENSSL_LIBS) -Wl,--no-whole-archive \
		-ldl -lpthread \
		-o $@

# ---------------------------------------------------------------------------
# libp11 EVP harness: exercises the libp11 ENGINE ↔ OpenSSL EVP bridge.
# Links OpenSSL statically (same reason as TLS harness: needs EVP_DigestSign,
# ENGINE_by_id etc. from our sanitized libcrypto).
# Suppresses ENGINE deprecation warnings — the ENGINE API is intentional here.
# ---------------------------------------------------------------------------
$(LIBP11_HARNESS): libp11_evp_fuzz.c common.h
	$(CC) $(CFLAGS_ALL) -Wno-deprecated-declarations $< \
		$(LINK_FLAGS) \
		-Wl,--whole-archive $(OPENSSL_LIBS) -Wl,--no-whole-archive \
		-ldl -lpthread \
		-o $@

# ---------------------------------------------------------------------------
# OpenSC PKCS#11 harness: loads opensc-pkcs11.so at runtime via dlopen.
# Does NOT link OpenSSL statically — opensc-pkcs11.so carries its own
# OpenSSL internally, and we do not use any OpenSSL API directly here.
# ---------------------------------------------------------------------------
$(OPENSC_HARNESS): opensc_pkcs11_fuzz.c common.h
	$(CC) $(CFLAGS_ALL) $< \
		$(LINK_FLAGS) \
		-ldl -lpthread \
		-o $@

# ---------------------------------------------------------------------------
# Corpus seed generation
# Each harness needs at least one seed in its corpus directory.
# ---------------------------------------------------------------------------
CORPUS_DIR := $(PROJECT_ROOT)/corpus

seeds:
	@echo "Generating seed corpus..."
	# pkcs11_sign: 11 mechanism selectors (0-10)
	@mkdir -p $(CORPUS_DIR)/pkcs11-sign
	@for i in 0 1 2 3 4 5 6 7 8 9; do \
		printf "\\x0$${i}AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" \
		> $(CORPUS_DIR)/pkcs11-sign/seed_mech$$i; \
	done
	@printf "\\x0aAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" \
		> $(CORPUS_DIR)/pkcs11-sign/seed_mech10
	# pkcs11_decrypt: 7 mechanism seeds (0-6, adds AES-CTR)
	@mkdir -p $(CORPUS_DIR)/pkcs11-decrypt
	@for i in 0 1 2 3 4 5 6; do \
		printf "\\x0$${i}\\x00\\x10BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB" \
		> $(CORPUS_DIR)/pkcs11-decrypt/seed_mech$$i; \
	done
	# pkcs11_findobj: seed with CKO_CERTIFICATE attribute
	@mkdir -p $(CORPUS_DIR)/pkcs11-findobj
	@printf "\\x01\\x00\\x00\\x00\\x00\\x04\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00" \
		> $(CORPUS_DIR)/pkcs11-findobj/seed_class_cert
	# pkcs11_createobj: 4 base object selectors with one fuzz attribute
	@mkdir -p $(CORPUS_DIR)/pkcs11-createobj
	@for i in 0 1 2 3; do \
		printf "\\x0$${i}\\x01\\x03\\x00\\x00\\x00\\x04\\x00JUNK" \
		> $(CORPUS_DIR)/pkcs11-createobj/seed_obj$$i; \
	done
	# pkcs11_session: 10 state-transition selectors
	@mkdir -p $(CORPUS_DIR)/pkcs11-session
	@for i in 0 1 2 3 4 5 6 7 8 9; do \
		printf "\\x0$${i}STATECHECK" \
		> $(CORPUS_DIR)/pkcs11-session/seed_op$$i; \
	done
	# pkcs11_state_machine: representative mixed call sequences
	@mkdir -p $(CORPUS_DIR)/pkcs11-state-machine
	@printf "\x08\x02payload\x0a\x0e\x0f\x00\x00" \
		> $(CORPUS_DIR)/pkcs11-state-machine/seed_digest_state
	@printf "\x01\x00\x00\x02\x03\x05\x01\x04DATA\x07\x06" \
		> $(CORPUS_DIR)/pkcs11-state-machine/seed_find_create
	@printf "\x0b\x00\x0chello\x0d\x10\x11\x04\x31\x32\x33\x34" \
		> $(CORPUS_DIR)/pkcs11-state-machine/seed_sign_login
	@printf "\x12\x13\x00\x00\x08\x02abc\x0a" \
		> $(CORPUS_DIR)/pkcs11-state-machine/seed_reopen_digest
	# pkcs11_concurrency: two-thread mixed workloads
	@mkdir -p $(CORPUS_DIR)/pkcs11-concurrency
	@printf "\x01\x00\x02\x00threadAthreadB" \
		> $(CORPUS_DIR)/pkcs11-concurrency/seed_digest_sign
	@printf "\x03\x01\x06\x01finderspayload" \
		> $(CORPUS_DIR)/pkcs11-concurrency/seed_find_create
	@printf "\x07\x01\x05\x00abcdefghijklmnopqrstuv" \
		> $(CORPUS_DIR)/pkcs11-concurrency/seed_encrypt_logout
	# pkcs11_token_reset: per-iteration PIN / token-management operations
	@mkdir -p $(CORPUS_DIR)/pkcs11-token-reset
	@printf "\x00\x041234" > $(CORPUS_DIR)/pkcs11-token-reset/seed_initpin
	@printf "\x01\x041234\x045678" > $(CORPUS_DIR)/pkcs11-token-reset/seed_setpin
	@printf "\x04\x0812345678\x09newlabel1" > $(CORPUS_DIR)/pkcs11-token-reset/seed_inittoken
	@printf "\x05\x043333\x044444" > $(CORPUS_DIR)/pkcs11-token-reset/seed_init_then_set
	# pkcs11_wrap: 8 operation seeds
	@mkdir -p $(CORPUS_DIR)/pkcs11-wrap
	@for i in 0 1 2 3 4 5 6 7; do \
		printf "\\x0$${i}CCCCCCCCCCCCCCCCCCCCCCCC" \
		> $(CORPUS_DIR)/pkcs11-wrap/seed_op$$i; \
	done
	# pkcs11_attrs: seeds with different object selectors
	@mkdir -p $(CORPUS_DIR)/pkcs11-attrs
	@for i in 0 1 2 3; do \
		printf "\\x0$${i}\\x01\\x01\\x00\\x00\\x00\\x00\\x04\\x00" \
		> $(CORPUS_DIR)/pkcs11-attrs/seed_obj$$i; \
	done
	# pkcs11_digest: 10 seeds (6 single + 4 multi, includes SHA224)
	@mkdir -p $(CORPUS_DIR)/pkcs11-digest
	@for i in 0 1 2 3 4 5 6 7 8 9; do \
		printf "\\x0$${i}\\x02DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD" \
		> $(CORPUS_DIR)/pkcs11-digest/seed_mech$$i; \
	done
	# pkcs11_multipart: one seed per operation (0-9)
	@mkdir -p $(CORPUS_DIR)/pkcs11-multipart
	@for i in 0 1 2 3 4 5 6 7 8 9; do \
		printf "\\x0$${i}\\x02EEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEE" \
		> $(CORPUS_DIR)/pkcs11-multipart/seed_op$$i; \
	done
	# pkcs11_keygen: 12 selectors (0-11, adds generic secret + EdDSA)
	@mkdir -p $(CORPUS_DIR)/pkcs11-keygen
	@for i in 0 1 2 3 4 5 6 7 8 9; do \
		printf "\\x0$${i}\\x20" > $(CORPUS_DIR)/pkcs11-keygen/seed_keytype$$i; \
	done
	@printf "\\x0a\\x20" > $(CORPUS_DIR)/pkcs11-keygen/seed_keytype10
	@printf "\\x0b\\x20" > $(CORPUS_DIR)/pkcs11-keygen/seed_keytype11
	# pkcs11_encrypt: 5 mechanism seeds (AES-ECB/CBC/CBC-PAD/CTR/GCM)
	@mkdir -p $(CORPUS_DIR)/pkcs11-encrypt
	@for i in 0 1 2 3 4; do \
		printf "\\x0$${i}FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF" \
		> $(CORPUS_DIR)/pkcs11-encrypt/seed_mech$$i; \
	done
	# pkcs11_verify: 8 selectors (fuzz-sig / valid-sig × 4 mechanisms)
	@mkdir -p $(CORPUS_DIR)/pkcs11-verify
	@for i in 0 1 2 3 4 5 6 7; do \
		printf "\\x0$${i}GGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGG" \
		> $(CORPUS_DIR)/pkcs11-verify/seed_op$$i; \
	done
	# pkcs11_random: 4 operation seeds
	@mkdir -p $(CORPUS_DIR)/pkcs11-random
	@for i in 0 1 2 3; do \
		printf "\\x0$${i}\\x20HHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHH" \
		> $(CORPUS_DIR)/pkcs11-random/seed_op$$i; \
	done
	# pkcs11_hmac: 6 HMAC/CMAC mechanism seeds
	@mkdir -p $(CORPUS_DIR)/pkcs11-hmac
	@for i in 0 1 2 3 4 5; do \
		printf "\\x0$${i}IIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIII" \
		> $(CORPUS_DIR)/pkcs11-hmac/seed_mech$$i; \
	done
	# libp11_evp: one seed per EVP operation (0=RSA-sign-SHA256,...,7=EC-multi)
	@mkdir -p $(CORPUS_DIR)/libp11-evp
	@for i in 0 1 2 3 4 5 6 7; do \
		printf "\\x0$${i}\\x02EEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEE" \
		> $(CORPUS_DIR)/libp11-evp/seed_op$$i; \
	done
	# opensc_pkcs11: 10 selectors (0-9), 6-byte header: sel+nattrs+slot_id
	@mkdir -p $(CORPUS_DIR)/opensc-pkcs11
	@for i in 0 1 2 3 4 5 6 7 8 9; do \
		printf "\\x0$${i}\\x02\\x00\\x00\\x00\\x00\\x01\\x02\\x03\\x04" \
		> $(CORPUS_DIR)/opensc-pkcs11/seed_op$$i; \
	done
	# tls: a minimal TLS 1.2 ClientHello (will be rejected, but exercises parsing)
	@mkdir -p $(CORPUS_DIR)/tls-pkcs11
	@printf '\\x16\\x03\\x01\\x00\\x28\\x01\\x00\\x00\\x24\\x03\\x03' \
		> $(CORPUS_DIR)/tls-pkcs11/seed_client_hello
	@echo "Seed corpus generated."

# ---------------------------------------------------------------------------
# Smoke test: run each harness briefly on its seed corpus
# ---------------------------------------------------------------------------
smoke-test: all seeds
	@echo "Running smoke tests (10 sec each)..."
	@export ASAN_OPTIONS="halt_on_error=1:detect_leaks=1:symbolize=1:detect_odr_violation=0"; \
	export UBSAN_OPTIONS="halt_on_error=1:print_stacktrace=1"; \
	export LSAN_OPTIONS="suppressions=$(PROJECT_ROOT)/fuzzing/lsan.suppressions"; \
	for h in $(ALL_TARGETS); do \
		echo ""; \
		echo "--- $$h ---"; \
		corpus_dir=$$(echo $$h | sed 's/_fuzz//;s/_/-/g'); \
		./$$h \
			-max_total_time=10 \
			-dict=$(DICT) \
			-artifact_prefix=$(PROJECT_ROOT)/crashes/raw/$$h- \
			$(CORPUS_DIR)/$$corpus_dir 2>&1 | tail -5; \
	done

clean:
	rm -f $(ALL_TARGETS)

# ---------------------------------------------------------------------------
# Coverage report: build instrumented binaries, replay corpus, open HTML.
# Delegates to fuzzing/gen-coverage.sh which uses Clang source-based coverage
# (llvm-profdata + llvm-cov).  Output: coverage/<harness>/index.html
# ---------------------------------------------------------------------------
.PHONY: coverage
coverage: seeds
	@bash $(PROJECT_ROOT)/fuzzing/gen-coverage.sh
