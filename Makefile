CC      ?= gcc
STD     := -std=c11
WARN    := -Wall -Wextra -Werror
INCLUDE := -Iinclude

# Base flags so any target (incl. a direct `make librawhttp.a`) compiles with
# the include path. release/debug override this with their own optimization
# and sanitizer settings.
CFLAGS  := $(STD) $(WARN) $(INCLUDE) -O2 -g

# Extra libs get appended here as phases land: -lssl -lcrypto (T2.5), -lpthread (T4.2)
LDLIBS  := -lssl -lcrypto -lpthread

SRC_DIR   := src
BUILD_DIR := build
BIN       := rawhttp
LIB       := librawhttp.a

TEST_DIR       := tests
TEST_BUILD_DIR := build/tests
TEST_BIN       := build/run_tests

SRCS     := $(wildcard $(SRC_DIR)/*.c)
OBJS     := $(patsubst $(SRC_DIR)/%.c,$(BUILD_DIR)/%.o,$(SRCS))

# Library = everything except main.c, so main.c stays CLI-only
LIB_SRCS := $(filter-out $(SRC_DIR)/main.c,$(SRCS))
LIB_OBJS := $(patsubst $(SRC_DIR)/%.c,$(BUILD_DIR)/%.o,$(LIB_SRCS))

# One binary per tests/*.c, each links the static lib
TEST_SRCS := $(wildcard $(TEST_DIR)/*.c)
TEST_BINS := $(patsubst $(TEST_DIR)/%.c,$(TEST_BUILD_DIR)/%,$(TEST_SRCS))

# libFuzzer targets (T5.3): one per tests/fuzz/fuzz_*.c
FUZZ_DIR         := tests/fuzz
FUZZ_BUILD_DIR   := build/fuzz
FUZZ_CC          ?= clang
FUZZ_HARNESS     := $(wildcard $(FUZZ_DIR)/fuzz_*.c)
FUZZ_BINS        := $(patsubst $(FUZZ_DIR)/%.c,$(FUZZ_BUILD_DIR)/%,$(FUZZ_HARNESS))
FUZZ_REPLAY_BINS := $(patsubst $(FUZZ_DIR)/%.c,$(FUZZ_BUILD_DIR)/%-replay,$(FUZZ_HARNESS))

.PHONY: all debug release test fuzz fuzz-replay clean

all: release

release: CFLAGS := $(STD) $(WARN) $(INCLUDE) -O2 -g
release: $(BIN)

debug: CFLAGS := $(STD) $(WARN) $(INCLUDE) -O0 -g -fsanitize=address,undefined
debug: LDFLAGS += -fsanitize=address,undefined
debug: $(BIN)

$(BIN): $(OBJS)
	$(CC) $(OBJS) -o $@ $(LDFLAGS) $(LDLIBS)

$(LIB): $(LIB_OBJS)
	ar rcs $@ $(LIB_OBJS)

$(BUILD_DIR)/%.o: $(SRC_DIR)/%.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

# Build + run every tests/*.c against the lib, under ASan/UBSan. Fails the
# target if any suite exits non-zero.
test: CFLAGS := $(STD) $(WARN) $(INCLUDE) -O0 -g -fsanitize=address,undefined
test: LDFLAGS += -fsanitize=address,undefined
test: $(TEST_BINS)
	@if [ -z "$(strip $(TEST_BINS))" ]; then \
		echo "no tests yet (tests/ is empty) - nothing to run"; \
	else \
		fail=0; \
		for t in $(TEST_BINS); do \
			echo "=== $$t ==="; \
			./$$t || fail=1; \
		done; \
		if [ $$fail -ne 0 ]; then echo "SOME TESTS FAILED"; exit 1; \
		else echo "ALL TESTS PASSED"; fi; \
	fi

$(TEST_BUILD_DIR)/%: $(TEST_DIR)/%.c $(LIB) | $(TEST_BUILD_DIR)
	$(CC) $(CFLAGS) $< $(LIB) -o $@ $(LDFLAGS) $(LDLIBS)

$(TEST_BUILD_DIR):
	mkdir -p $(TEST_BUILD_DIR)

# --- Fuzzing (T5.3) ---------------------------------------------------------
# `make fuzz` needs clang (libFuzzer). Then run a target against its corpus:
#   ./build/fuzz/fuzz_response tests/fuzz/corpus/response
# `make fuzz-replay` needs only gcc: it builds each target with a standalone
# driver and replays the seed corpus once (crash repro + CI smoke, no clang).

fuzz: $(FUZZ_BINS)
	@echo "fuzz targets: $(FUZZ_BINS)"
	@echo "run e.g.: ./$(FUZZ_BUILD_DIR)/fuzz_response $(FUZZ_DIR)/corpus/response"

$(FUZZ_BUILD_DIR)/%: $(FUZZ_DIR)/%.c $(LIB_SRCS) | $(FUZZ_BUILD_DIR)
	$(FUZZ_CC) $(STD) $(INCLUDE) -I$(FUZZ_DIR) -g -O1 \
		-fsanitize=fuzzer,address,undefined $(FUZZ_DIR)/$*.c $(LIB_SRCS) -o $@ $(LDLIBS)

fuzz-replay: $(FUZZ_REPLAY_BINS)
	@for b in $(FUZZ_REPLAY_BINS); do \
		name=$${b##*/}; sub=$${name%-replay}; sub=$${sub#fuzz_}; \
		echo "=== $$b (corpus: $$sub) ==="; \
		$$b $(FUZZ_DIR)/corpus/$$sub/* || exit 1; \
	done; \
	echo "FUZZ REPLAY OK"

$(FUZZ_BUILD_DIR)/%-replay: $(FUZZ_DIR)/%.c $(FUZZ_DIR)/standalone_main.c $(LIB_SRCS) | $(FUZZ_BUILD_DIR)
	$(CC) $(STD) $(INCLUDE) -I$(FUZZ_DIR) -g -O1 -fsanitize=address,undefined \
		$(FUZZ_DIR)/$*.c $(FUZZ_DIR)/standalone_main.c $(LIB_SRCS) -o $@ $(LDLIBS)

$(FUZZ_BUILD_DIR):
	mkdir -p $(FUZZ_BUILD_DIR)

clean:
	rm -rf $(BUILD_DIR) $(BIN) $(LIB)

