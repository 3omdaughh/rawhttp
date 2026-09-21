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

.PHONY: all debug release test clean

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

clean:
	rm -rf $(BUILD_DIR) $(BIN) $(LIB)

