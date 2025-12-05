# BYVALVER - Null-Byte Elimination Framework
# Complete CLI Tool Build Configuration

# Compiler and flags
CC = gcc
CFLAGS = -Wall -Wextra -pedantic -std=c99 -O2
LDFLAGS = -lcapstone -lm

# Directories
SRC_DIR = src
BIN_DIR = bin
TARGET = byvalver

# Get all C files, excluding old/duplicate versions
ALL_SRCS = $(wildcard $(SRC_DIR)/*.c)

# Exclude files:
# - lib_api.c (library-specific, not needed for CLI)
# - fix_*.c (old versions of strategies)
# - conservative_mov_original.c (old version)
# - arithmetic_substitution_strategies.c (duplicate with arithmetic_strategies.c)
# - test_strategies.c (test-only code)
# - cli.c will be included separately to ensure proper build order
EXCLUDE_FILES = $(SRC_DIR)/lib_api.c \
                $(SRC_DIR)/fix_arithmetic_strategies.c \
                $(SRC_DIR)/fix_general_strategies.c \
                $(SRC_DIR)/fix_mov_strategies.c \
                $(SRC_DIR)/conservative_mov_original.c \
                $(SRC_DIR)/arithmetic_substitution_strategies.c \
                $(SRC_DIR)/test_strategies.c

# Include CLI files explicitly
CLI_SRCS = $(SRC_DIR)/cli.c
NON_CLI_SRCS = $(filter-out $(CLI_SRCS), $(ALL_SRCS))

# Final source list
SRCS = $(CLI_SRCS) $(NON_CLI_SRCS)

# Obfuscation modules (Pass 1 of biphasic architecture)
OBFUSCATION_SRCS = $(SRC_DIR)/obfuscation_strategy_registry.c \
                   $(SRC_DIR)/obfuscation_strategies.c

# Final source list - pic_generation.c is already included in ALL_SRCS via wildcard
SRCS = $(filter-out $(EXCLUDE_FILES), $(ALL_SRCS))

# Object files
OBJS = $(patsubst $(SRC_DIR)/%.c, $(BIN_DIR)/%.o, $(SRCS))

# Phony targets
.PHONY: all clean clean-all info test debug release

# Default target
all: decoder.h $(BIN_DIR)/$(TARGET)

# Debug build
debug: CFLAGS += -g -O0 -DDEBUG -fsanitize=address -fsanitize=undefined
debug: LDFLAGS += -fsanitize=address -fsanitize=undefined
debug: all

# Release build (optimized)
release: CFLAGS += -O3 -march=native -DNDEBUG
release: all

# Static build
static: LDFLAGS = -static -lcapstone
static: all

# Create bin directory
$(BIN_DIR):
	@mkdir -p $(BIN_DIR)

# Build decoder stub from assembly
decoder.bin: decoder.asm
	@echo "[NASM] Assembling decoder stub..."
	@nasm -f bin -o $@ $<

# Generate C header from decoder binary
decoder.h: decoder.bin
	@echo "[XXD] Generating decoder header..."
	@xxd -i $< > $@

# Link final executable
$(BIN_DIR)/$(TARGET): $(BIN_DIR) $(OBJS)
	@echo "[LD] Linking $(TARGET)..."
	@$(CC) $(CFLAGS) -o $@ $(OBJS) $(LDFLAGS)
	@echo "[OK] Built $(TARGET) successfully ($(words $(OBJS)) object files)"

# Compile source files
$(BIN_DIR)/%.o: $(SRC_DIR)/%.c decoder.h
	@echo "[CC] Compiling $<..."
	@$(CC) $(CFLAGS) -c -o $@ $<

# Clean build artifacts
clean:
	@echo "[CLEAN] Removing build artifacts..."
	@rm -rf $(BIN_DIR)/* decoder.bin decoder.h
	@echo "[OK] Clean complete"

# Clean everything including backups
clean-all: clean
	@echo "[CLEAN-ALL] Removing all generated files..."
	@rm -rf $(BIN_DIR)
	@echo "[OK] Clean-all complete"

# Show build information
info:
	@echo "BYVALVER Build Configuration"
	@echo "============================="
	@echo "CC:       $(CC)"
	@echo "CFLAGS:   $(CFLAGS)"
	@echo "LDFLAGS:  $(LDFLAGS)"
	@echo "TARGET:   $(BIN_DIR)/$(TARGET)"
	@echo "SOURCES:  $(words $(SRCS)) C files"
	@echo "EXCLUDED: $(words $(EXCLUDE_FILES)) files"
	@echo "OBJECTS:  $(words $(OBJS)) object files"
	@echo ""
	@echo "Strategy Modules:"
	@echo "  - $(shell echo $(SRCS) | tr ' ' '\n' | grep -c '_strategies\.c$$') strategy files"
	@echo "  - Core: main.c, core.c, utils.c, strategy_registry.c"
	@echo ""

# Test build (quick check)
test: all
	@echo "[TEST] Verifying build..."
	@if [ -f "$(BIN_DIR)/$(TARGET)" ]; then \
		echo "[OK] Executable built successfully"; \
		ls -lh $(BIN_DIR)/$(TARGET); \
		echo ""; \
		echo "Run: ./$(BIN_DIR)/$(TARGET) --help"; \
	else \
		echo "[FAIL] Executable not found"; \
		exit 1; \
	fi

# Check dependencies
check-deps:
	@echo "[CHECK] Verifying dependencies..."
	@which gcc > /dev/null || (echo "[FAIL] gcc not found" && exit 1)
	@which nasm > /dev/null || (echo "[FAIL] nasm not found" && exit 1)
	@which xxd > /dev/null || (echo "[FAIL] xxd not found" && exit 1)
	@pkg-config --exists capstone || (echo "[FAIL] libcapstone-dev not found" && exit 1)
	@echo "[OK] All dependencies present"

# Install target
install: all
	@echo "[INSTALL] Installing byvalver..."
	@mkdir -p /usr/local/bin
	@cp $(BIN_DIR)/$(TARGET) /usr/local/bin/
	@chmod 755 /usr/local/bin/$(TARGET)
	@echo "[OK] Installed to /usr/local/bin/$(TARGET)"

# Install man page
install-man: byvalver.1
	@echo "[INSTALL] Installing man page..."
	@mkdir -p /usr/local/share/man/man1
	@cp byvalver.1 /usr/local/share/man/man1/
	@chmod 644 /usr/local/share/man/man1/byvalver.1
	@echo "[OK] Man page installed to /usr/local/share/man/man1/byvalver.1"
	@echo "[INFO] Run 'man byvalver' to view the manual page"

# Uninstall target
uninstall:
	@echo "[UNINSTALL] Removing byvalver..."
	@rm -f /usr/local/bin/$(TARGET)
	@rm -f /usr/local/share/man/man1/byvalver.1
	@echo "[OK] Uninstalled byvalver"

# Format code (if clang-format is available)
format:
	@if which clang-format > /dev/null 2>&1; then \
		echo "[FORMAT] Running clang-format..."; \
		find $(SRC_DIR) -name '*.c' -o -name '*.h' | xargs clang-format -i; \
		echo "[OK] Code formatted"; \
	else \
		echo "[SKIP] clang-format not installed"; \
	fi

# Static analysis (if cppcheck is available)
lint:
	@if which cppcheck > /dev/null 2>&1; then \
		echo "[LINT] Running cppcheck..."; \
		cppcheck --enable=all --suppress=missingIncludeSystem $(SRC_DIR)/*.c; \
	else \
		echo "[SKIP] cppcheck not installed"; \
	fi
