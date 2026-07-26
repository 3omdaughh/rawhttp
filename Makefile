CC      ?= gcc
STD     := -std=c11
WARN    := -Wall -Wextra -Werror
INCLUDE := -Iinclude

# Extra libs get appended here as phases land: -lssl -lcrypto (T2.5), -lpthread (T4.2)
LDLIBS  :=

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

# T5.1 wires real test sources into TEST_BIN once tests/ has content.
test: debug
	@if [ -z "$$(ls -A $(TEST_DIR) 2>/dev/null | grep -v .gitkeep)" ]; then \
		echo "no tests yet (tests/ is empty) - nothing to run"; \
	else \
		echo "test harness not wired yet - see T5.1"; \
	fi

clean:
	rm -rf $(BUILD_DIR) $(BIN) $(LIB)

