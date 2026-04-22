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
		printf '%b' "\\0$${i}AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" \
		> $(CORPUS_DIR)/pkcs11-sign/seed_mech$$i; \
	done
	@printf '%b' '\012AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' \
		> $(CORPUS_DIR)/pkcs11-sign/seed_mech10
	# pkcs11_decrypt: 7 mechanism seeds (0-6, adds AES-CTR)
	@mkdir -p $(CORPUS_DIR)/pkcs11-decrypt
	@for i in 0 1 2 3 4 5 6; do \
		printf '%b' "\\0$${i}\\000\\020BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB" \
		> $(CORPUS_DIR)/pkcs11-decrypt/seed_mech$$i; \
	done
	# pkcs11_findobj: seed with CKO_CERTIFICATE attribute
	@mkdir -p $(CORPUS_DIR)/pkcs11-findobj
	@printf '%b' '\001\000\000\000\000\004\000\000\000\000\000\000\000\000\000' \
		> $(CORPUS_DIR)/pkcs11-findobj/seed_class_cert
	# pkcs11_createobj: 4 base object selectors with one fuzz attribute
	@mkdir -p $(CORPUS_DIR)/pkcs11-createobj
	@for i in 0 1 2 3; do \
		printf '%b' "\\0$${i}\\001\\003\\000\\000\\000\\004\\000JUNK" \
		> $(CORPUS_DIR)/pkcs11-createobj/seed_obj$$i; \
	done
	# pkcs11_session: 10 state-transition selectors
	@mkdir -p $(CORPUS_DIR)/pkcs11-session
	@for i in 0 1 2 3 4 5 6 7 8 9; do \
		printf '%b' "\\0$${i}STATECHECK" \
		> $(CORPUS_DIR)/pkcs11-session/seed_op$$i; \
	done
	# pkcs11_state_machine: representative mixed call sequences
	@mkdir -p $(CORPUS_DIR)/pkcs11-state-machine
	@printf '%b' '\010\002payload\012\016\017\000\000' \
		> $(CORPUS_DIR)/pkcs11-state-machine/seed_digest_state
	@printf '%b' '\001\000\000\002\003\005\001\004DATA\007\006' \
		> $(CORPUS_DIR)/pkcs11-state-machine/seed_find_create
	@printf '%b%s' '\013\000\014hello\015\020\021\004' '1234' \
		> $(CORPUS_DIR)/pkcs11-state-machine/seed_sign_login
	@printf '%b' '\022\023\000\000\010\002abc\012' \
		> $(CORPUS_DIR)/pkcs11-state-machine/seed_reopen_digest
	@printf '%b' '\012\002\013\005hello\023\001\001\001\024\001\000\000\014' \
		> $(CORPUS_DIR)/pkcs11-state-machine/seed_cross_session_state
	@printf '%b' '\015\000\016\005hello\017\020\000\021\005hello\022' \
		> $(CORPUS_DIR)/pkcs11-state-machine/seed_sign_verify_roundtrip
	@printf '%b' '\033\020\027\030\031\032' \
		> $(CORPUS_DIR)/pkcs11-state-machine/seed_encrypt_decrypt_chain
	@printf '%b' '\007\000\004DATAA\006\006\002\003\010\006B\006\007\002\004\011\006\011\007' \
		> $(CORPUS_DIR)/pkcs11-state-machine/seed_create_copy_destroy
	@printf '%b%s%b' '\025\026\004' '1234' '\001\002\001\002\034\002\000\000' \
		> $(CORPUS_DIR)/pkcs11-state-machine/seed_logout_relogin_close
	# pkcs11_concurrency: two-thread mixed workloads
	@mkdir -p $(CORPUS_DIR)/pkcs11-concurrency
	@printf '%b' '\001\000\002\000threadAthreadB' \
		> $(CORPUS_DIR)/pkcs11-concurrency/seed_digest_sign
	@printf '%b' '\003\001\006\001finderspayload' \
		> $(CORPUS_DIR)/pkcs11-concurrency/seed_find_create
	@printf '%b' '\007\001\005\000abcdefghijklmnopqrstuv' \
		> $(CORPUS_DIR)/pkcs11-concurrency/seed_encrypt_logout
	# pkcs11_token_reset: per-iteration PIN / token-management operations
	@mkdir -p $(CORPUS_DIR)/pkcs11-token-reset
	@printf '%b%s' '\000\004' '1234' > $(CORPUS_DIR)/pkcs11-token-reset/seed_initpin
	@printf '%b%s%b%s' '\001\004' '1234' '\004' '5678' > $(CORPUS_DIR)/pkcs11-token-reset/seed_setpin
	@printf '%b%s%b%s' '\004\010' '12345678' '\011' 'newlabel1' > $(CORPUS_DIR)/pkcs11-token-reset/seed_inittoken
	@printf '%b%s%b%s' '\005\004' '3333' '\004' '4444' > $(CORPUS_DIR)/pkcs11-token-reset/seed_init_then_set
	# pkcs11_wrap: 8 operation seeds
	@mkdir -p $(CORPUS_DIR)/pkcs11-wrap
	@for i in 0 1 2 3 4 5 6 7; do \
		printf '%b' "\\0$${i}CCCCCCCCCCCCCCCCCCCCCCCC" \
		> $(CORPUS_DIR)/pkcs11-wrap/seed_op$$i; \
	done
	# pkcs11_attrs: seeds with different object selectors
	@mkdir -p $(CORPUS_DIR)/pkcs11-attrs
	@for i in 0 1 2 3; do \
		printf '%b' "\\0$${i}\\001\\001\\000\\000\\000\\000\\004\\000" \
		> $(CORPUS_DIR)/pkcs11-attrs/seed_obj$$i; \
	done
	# pkcs11_digest: 10 seeds (6 single + 4 multi, includes SHA224)
	@mkdir -p $(CORPUS_DIR)/pkcs11-digest
	@for i in 0 1 2 3 4 5 6 7 8 9; do \
		printf '%b' "\\0$${i}\\002DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD" \
		> $(CORPUS_DIR)/pkcs11-digest/seed_mech$$i; \
	done
	# pkcs11_multipart: one seed per operation (0-9)
	@mkdir -p $(CORPUS_DIR)/pkcs11-multipart
	@for i in 0 1 2 3 4 5 6 7 8 9; do \
		printf '%b' "\\0$${i}\\002EEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEE" \
		> $(CORPUS_DIR)/pkcs11-multipart/seed_op$$i; \
	done
	# pkcs11_keygen: 16 selectors (0-15, adds more curves and RSA-2048)
	@mkdir -p $(CORPUS_DIR)/pkcs11-keygen
	@for i in 0 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15; do \
		printf '%b' "\\$$(printf '%03o' $$i)\\040" > $(CORPUS_DIR)/pkcs11-keygen/seed_keytype$$i; \
	done
	# pkcs11_encrypt: 5 mechanism seeds (AES-ECB/CBC/CBC-PAD/CTR/GCM)
	@mkdir -p $(CORPUS_DIR)/pkcs11-encrypt
	@for i in 0 1 2 3 4; do \
		printf '%b' "\\0$${i}FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF" \
		> $(CORPUS_DIR)/pkcs11-encrypt/seed_mech$$i; \
	done
	# pkcs11_verify: 8 selectors (fuzz-sig / valid-sig × 4 mechanisms)
	@mkdir -p $(CORPUS_DIR)/pkcs11-verify
	@for i in 0 1 2 3 4 5 6 7; do \
		printf '%b' "\\0$${i}GGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGG" \
		> $(CORPUS_DIR)/pkcs11-verify/seed_op$$i; \
	done
	# pkcs11_random: 4 operation seeds
	@mkdir -p $(CORPUS_DIR)/pkcs11-random
	@for i in 0 1 2 3; do \
		printf '%b' "\\0$${i}\\040HHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHH" \
		> $(CORPUS_DIR)/pkcs11-random/seed_op$$i; \
	done
	# pkcs11_hmac: 6 HMAC/CMAC mechanism seeds
	@mkdir -p $(CORPUS_DIR)/pkcs11-hmac
	@for i in 0 1 2 3 4 5; do \
		printf '%b' "\\0$${i}IIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIII" \
		> $(CORPUS_DIR)/pkcs11-hmac/seed_mech$$i; \
	done
	# libp11_evp: one seed per EVP operation (0=RSA-sign-SHA256,...,7=EC-multi)
	@mkdir -p $(CORPUS_DIR)/libp11-evp
	@for i in 0 1 2 3 4 5 6 7; do \
		printf '%b' "\\0$${i}\\002EEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEE" \
		> $(CORPUS_DIR)/libp11-evp/seed_op$$i; \
	done
	# opensc_pkcs11: 10 selectors (0-9), 6-byte header: sel+nattrs+slot_id
	@mkdir -p $(CORPUS_DIR)/opensc-pkcs11
	@for i in 0 1 2 3 4 5 6 7 8 9; do \
		printf '%b' "\\000\\000\\000\\000\\0$${i}\\002\\001\\002\\003\\004" \
		> $(CORPUS_DIR)/opensc-pkcs11/seed_op$$i; \
	done
	@printf '%b' '\000\000\000\000\000\001\002\003\014\000' \
		> $(CORPUS_DIR)/opensc-pkcs11/seed_info_mech_reinit
	@printf '%b' '\000\000\000\000\001\003\004\005\006\001\000\002A\007\001\001\010' \
		> $(CORPUS_DIR)/opensc-pkcs11/seed_slot_session_find_closeall
	@printf '%b' '\377\377\377\177\001\002\003\004\015\000\000\000\000\016\001\017' \
		> $(CORPUS_DIR)/opensc-pkcs11/seed_invalid_slot_mech_attr_walk
	@printf '%b%s%b' '\000\000\000\000\003\001\001\004\012\004' '1234' '\013\011\001\011' \
		> $(CORPUS_DIR)/opensc-pkcs11/seed_session_login_close
	@printf '%b' '\000\000\000\000\014\001\002\003\003\001\001\006\002\001A\017' \
		> $(CORPUS_DIR)/opensc-pkcs11/seed_reinit_then_find
	# tls: a minimal TLS 1.2 ClientHello
	@mkdir -p $(CORPUS_DIR)/tls-pkcs11
	@printf '%b' '\026\003\001\000\050\001\000\000\044\003\003' \
		> $(CORPUS_DIR)/tls-pkcs11/seed_client_hello
	# tls 1.3 seed (cfg & 1 sets min version to 1.3)
	@printf '%b' '\001\001\000' \
		> $(CORPUS_DIR)/tls-pkcs11/seed_tls13
	@printf '%b' '\000\000\000\001\000\001\007' \
		> $(CORPUS_DIR)/tls-pkcs11/seed_handshake_pingpong
	@printf '%b%s%b' '\002\000\002' 'hello from client' '\001\003\007' \
		> $(CORPUS_DIR)/tls-pkcs11/seed_client_write_server_read
	@printf '%b%s%b' '\004\000\004' 'reply from server' '\005\007\006' \
		> $(CORPUS_DIR)/tls-pkcs11/seed_server_write_client_read
	@printf '%b%s%b' '\020\020\000\001\002' 'GET / HTTP/1.0\r\n\r\n' '\003\004data\005\010\t' \
		> $(CORPUS_DIR)/tls-pkcs11/seed_handshake_io_mix
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
