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
                $(PROJECT_ROOT)/src/libp11/src \
                $(PROJECT_ROOT)/src/softhsm2/src/lib/pkcs11
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

# ---------------------------------------------------------------------------
# Harness targets
# ---------------------------------------------------------------------------
PKCS11_HARNESSES := \
    pkcs11_sign_fuzz \
    pkcs11_decrypt_fuzz \
    pkcs11_findobj_fuzz \
    pkcs11_wrap_fuzz \
    pkcs11_attrs_fuzz \
    pkcs11_digest_fuzz \
    pkcs11_multipart_fuzz \
    pkcs11_keygen_fuzz

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
	# pkcs11_sign: one seed per mechanism selector byte (0..7)
	@mkdir -p $(CORPUS_DIR)/pkcs11-sign
	@for i in 0 1 2 3 4 5 6 7; do \
		printf "\\x0$${i}AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" \
		> $(CORPUS_DIR)/pkcs11-sign/seed_mech$$i; \
	done
	# pkcs11_decrypt: 6 mechanism seeds
	@mkdir -p $(CORPUS_DIR)/pkcs11-decrypt
	@for i in 0 1 2 3 4 5; do \
		printf "\\x0$${i}\\x00\\x00BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB" \
		> $(CORPUS_DIR)/pkcs11-decrypt/seed_mech$$i; \
	done
	# pkcs11_findobj: seed with CKO_CERTIFICATE attribute
	@mkdir -p $(CORPUS_DIR)/pkcs11-findobj
	@printf "\\x01\\x00\\x00\\x00\\x00\\x04\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00" \
		> $(CORPUS_DIR)/pkcs11-findobj/seed_class_cert
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
	# pkcs11_digest: one seed per mechanism/mode (0=SHA1,1=SHA256,...,7=SHA512-multi)
	@mkdir -p $(CORPUS_DIR)/pkcs11-digest
	@for i in 0 1 2 3 4 5 6 7; do \
		printf "\\x0$${i}\\x02DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD" \
		> $(CORPUS_DIR)/pkcs11-digest/seed_mech$$i; \
	done
	# pkcs11_multipart: one seed per operation (0=Sign-RSA,...,9=Decrypt-GCM-multi)
	@mkdir -p $(CORPUS_DIR)/pkcs11-multipart
	@for i in 0 1 2 3 4 5 6 7 8 9; do \
		printf "\\x0$${i}\\x02EEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEE" \
		> $(CORPUS_DIR)/pkcs11-multipart/seed_op$$i; \
	done
	# pkcs11_keygen: one seed per key type selector (0=RSA-512,...,9=AES-fuzz)
	@mkdir -p $(CORPUS_DIR)/pkcs11-keygen
	@for i in 0 1 2 3 4 5 6 7 8 9; do \
		printf "\\x0$${i}\\x20" > $(CORPUS_DIR)/pkcs11-keygen/seed_keytype$$i; \
	done
	# libp11_evp: one seed per EVP operation (0=RSA-sign-SHA256,...,7=EC-multi)
	@mkdir -p $(CORPUS_DIR)/libp11-evp
	@for i in 0 1 2 3 4 5 6 7; do \
		printf "\\x0$${i}\\x02EEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEE" \
		> $(CORPUS_DIR)/libp11-evp/seed_op$$i; \
	done
	# opensc_pkcs11: one seed per operation (0=slot-info,...,7=close-all)
	@mkdir -p $(CORPUS_DIR)/opensc-pkcs11
	@for i in 0 1 2 3 4 5 6 7; do \
		printf "\\x0$${i}\\x02\\x00\\x04\\x01\\x02\\x03\\x04" \
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
coverage:
	@bash $(PROJECT_ROOT)/fuzzing/gen-coverage.sh
