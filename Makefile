# BYVALVER Makefile - Enterprise-grade Shellcode Null-Byte Eliminator
# Advanced build system with multiple targets and configurations

# Compiler and flags
CC = gcc
CFLAGS_BASE = -Wall -Wextra -Wpedantic -std=c99 -O2
CFLAGS_DEBUG = -g -DDEBUG -fsanitize=address,undefined
CFLAGS_RELEASE = -O3 -DNDEBUG
LDFLAGS_BASE = -lcapstone
LDFLAGS_DEBUG = -fsanitize=address,undefined
LDFLAGS_STATIC = -static

# Source and directory configuration
SRC_DIR = src
BIN_DIR = bin
TEST_DIR = tests
OBJ_DIR = $(BIN_DIR)/obj

# Target name
TARGET = byvalver
TEST_TARGET = test_byvalver

# Find all source files (excluding the fix files)
SRCS = $(wildcard $(SRC_DIR)/*.c)
# Filter out the 'fix_' files since they're not part of the main build
FILTERED_SRCS = $(filter-out $(SRC_DIR)/fix_%.c, $(SRCS))
OBJS = $(patsubst $(SRC_DIR)/%.c,$(OBJ_DIR)/%.o,$(FILTERED_SRCS))

# Main source files that are part of the official build
MAIN_SRCS = $(SRC_DIR)/main.c $(SRC_DIR)/core.c $(SRC_DIR)/utils.c $(SRC_DIR)/strategy_registry.c $(SRC_DIR)/context_preservation_strategies.c $(SRC_DIR)/sequence_preservation_strategies.c $(SRC_DIR)/lea_strategies.c $(SRC_DIR)/conservative_strategies.c $(SRC_DIR)/conservative_mov_original.c $(SRC_DIR)/mov_strategies.c $(SRC_DIR)/arithmetic_strategies.c $(SRC_DIR)/adc_strategies.c $(SRC_DIR)/sbb_strategies.c $(SRC_DIR)/setcc_strategies.c $(SRC_DIR)/imul_strategies.c $(SRC_DIR)/fpu_strategies.c $(SRC_DIR)/sldt_strategies.c $(SRC_DIR)/sldt_replacement_strategy.c $(SRC_DIR)/retf_strategies.c $(SRC_DIR)/arpl_strategies.c $(SRC_DIR)/bound_strategies.c $(SRC_DIR)/xchg_strategies.c $(SRC_DIR)/memory_strategies.c $(SRC_DIR)/cmp_strategies.c $(SRC_DIR)/test_strategies.c $(SRC_DIR)/bt_strategies.c $(SRC_DIR)/jump_strategies.c $(SRC_DIR)/loop_strategies.c $(SRC_DIR)/general_strategies.c $(SRC_DIR)/hash_utils.c $(SRC_DIR)/anti_debug_strategies.c $(SRC_DIR)/shift_strategy.c $(SRC_DIR)/peb_strategies.c $(SRC_DIR)/advanced_transformations.c $(SRC_DIR)/getpc_strategies.c $(SRC_DIR)/movzx_strategies.c $(SRC_DIR)/ror_rol_strategies.c $(SRC_DIR)/indirect_call_strategies.c $(SRC_DIR)/ret_strategies.c
MAIN_OBJS = $(patsubst $(SRC_DIR)/%.c,$(OBJ_DIR)/%.o,$(MAIN_SRCS))

# Test source files
TEST_SRCS = test_byvalver.c
TEST_OBJS = $(patsubst %.c,$(OBJ_DIR)/%.o,$(notdir $(TEST_SRCS)))

# For backward compatibility, map fix files to main strategy files
FIXED_MOV_SRC = $(SRC_DIR)/fix_mov_strategies.c
FIXED_ARITHMETIC_SRC = $(SRC_DIR)/fix_arithmetic_strategies.c
FIXED_GENERAL_SRC = $(SRC_DIR)/fix_general_strategies.c

# If fix files exist, use them instead of main strategy files
$(OBJ_DIR)/mov_strategies.o: $(FIXED_MOV_SRC) | $(OBJ_DIR)
	@echo "  CC      $(FIXED_MOV_SRC) -> $@"
	$(Q)$(CC) $(CFLAGS) -I$(SRC_DIR) -c -o $@ $(FIXED_MOV_SRC)

$(OBJ_DIR)/arithmetic_strategies.o: $(FIXED_ARITHMETIC_SRC) | $(OBJ_DIR)
	@echo "  CC      $(FIXED_ARITHMETIC_SRC) -> $@"
	$(Q)$(CC) $(CFLAGS) -I$(SRC_DIR) -c -o $@ $(FIXED_ARITHMETIC_SRC)

$(OBJ_DIR)/general_strategies.o: $(FIXED_GENERAL_SRC) | $(OBJ_DIR)
	@echo "  CC      $(FIXED_GENERAL_SRC) -> $@"
	$(Q)$(CC) $(CFLAGS) -I$(SRC_DIR) -c -o $@ $(FIXED_GENERAL_SRC)

# Default target
.DEFAULT_GOAL := all

# Build configurations
DEBUG ?= 0
STATIC ?= 0
VERBOSE ?= 0

ifeq ($(DEBUG), 1)
    CFLAGS = $(CFLAGS_BASE) $(CFLAGS_DEBUG)
    LDFLAGS = $(LDFLAGS_BASE) $(LDFLAGS_DEBUG)
    BUILD_TYPE = debug
else
    CFLAGS = $(CFLAGS_BASE) $(CFLAGS_RELEASE)
    LDFLAGS = $(LDFLAGS_BASE)
    BUILD_TYPE = release
endif

ifeq ($(STATIC), 1)
    LDFLAGS += $(LDFLAGS_STATIC)
    BUILD_TYPE := $(BUILD_TYPE)-static
endif

# Verbose output
ifeq ($(VERBOSE), 1)
    Q :=
else
    Q := @
endif

# Phony targets
.PHONY: all clean test debug release install uninstall help format lint check-deps

# Main build target
all: decoder.h $(BIN_DIR)/$(TARGET)

# Create necessary directories
$(BIN_DIR) $(OBJ_DIR):
	@mkdir -p $@

# Compile main source files to object files
$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c decoder.h | $(OBJ_DIR)
	@echo "  CC      $<"
	$(Q)$(CC) $(CFLAGS) -I$(SRC_DIR) -c -o $@ $<

# Link the main executable
$(BIN_DIR)/$(TARGET): $(MAIN_OBJS) | $(BIN_DIR)
	@echo "  LINK    $(TARGET) [$(BUILD_TYPE)]"
	$(Q)$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

# Generate decoder header from assembly
decoder.bin: decoder.asm
	@echo "  NASM    $< -> $@"
	$(Q)nasm -f bin -o $@ $<

decoder.h: decoder.bin
	@echo "  XXD     $< -> $@"
	$(Q)xxd -i $< > $@

# Debug build target
debug:
	@$(MAKE) DEBUG=1

# Release build target
release:
	@$(MAKE) DEBUG=0

# Static build target
static:
	@$(MAKE) STATIC=1

# Test target
test: $(BIN_DIR)/$(TEST_TARGET)
	@echo "  RUNNING TESTS..."
	$(Q)$(BIN_DIR)/$(TEST_TARGET)

# Build test executable if test sources exist
$(BIN_DIR)/$(TEST_TARGET): $(TEST_SRCS) $(MAIN_OBJS) | $(BIN_DIR)
	@echo "  CCLD    $@"
	$(Q)$(CC) $(CFLAGS) -I$(SRC_DIR) -o $@ $< $(filter-out $(OBJ_DIR)/main.o,$(MAIN_OBJS)) $(LDFLAGS)

# Install target
install: $(BIN_DIR)/$(TARGET)
	@echo "  INSTALL $(TARGET) to /usr/local/bin"
	$(Q)install -m 755 $(BIN_DIR)/$(TARGET) /usr/local/bin/

# Uninstall target
uninstall:
	@echo "  UNINSTALL $(TARGET) from /usr/local/bin"
	$(Q)rm -f /usr/local/bin/$(TARGET)

# Format code using astyle or clang-format if available
format:
	@echo "  FORMATTING source code..."
	$(Q)if command -v clang-format > /dev/null; then \
		find $(SRC_DIR) -name "*.c" -o -name "*.h" | xargs clang-format -i; \
	elif command -v astyle > /dev/null; then \
		astyle --style=allman --indent=spaces=4 --pad-oper --pad-header --keep-one-line-blocks --keep-one-line-statements *.c src/*.c src/*.h; \
	else \
		echo "Warning: Neither clang-format nor astyle found. Install one to format code."; \
	fi

# Lint code using cppcheck if available
lint:
	@echo "  LINTING source code..."
	$(Q)if command -v cppcheck > /dev/null; then \
		cppcheck --enable=all --std=c99 --verbose --quiet $(SRC_DIR)/; \
	else \
		echo "Warning: cppcheck not found. Install cppcheck for linting."; \
	fi

# Check build dependencies
check-deps:
	@echo "Checking build dependencies..."
	@command -v $(CC) > /dev/null || (echo "Error: $(CC) not found"; exit 1)
	@command -v nasm > /dev/null || (echo "Error: nasm not found"; exit 1)
	@command -v xxd > /dev/null || (echo "Error: xxd not found"; exit 1)
	@echo "#include <capstone/capstone.h>" | $(CC) -xc -E - > /dev/null 2>&1 || (echo "Error: capstone library not found"; exit 1)
	@echo "All dependencies satisfied."

# Clean build artifacts
clean:
	@echo "  CLEAN   build artifacts"
	$(Q)rm -rf $(BIN_DIR)/*
	$(Q)rm -f decoder.bin decoder.h
	$(Q)find . -name "*.o" -delete
	$(Q)echo "Clean completed."

# Advanced clean including backups
clean-all: clean
	@echo "  CLEAN   all artifacts including backups"
	$(Q)find . -name "*~" -delete
	$(Q)find . -name "*.bak" -delete
	$(Q)find . -name ".DS_Store" -delete
	$(Q)find . -name "*.pyc" -delete
	$(Q)find . -name "__pycache__" -type d -exec rm -rf {} +

# Create a distributable archive
dist: clean
	@echo "  ARCHIVE creating distributable package"
	$(Q)cd .. && tar --exclude='.git' --exclude='*.tar.gz' -czf byvalver-$(shell date +%Y%m%d).tar.gz $(notdir $(CURDIR))
	@echo "Distribution archive created."

# Help target
help:
	@echo "BYVALVER Build System"
	@echo "======================"
	@echo ""
	@echo "Usage: make [TARGET] [OPTIONS]"
	@echo ""
	@echo "Targets:"
	@echo "  all        - Build the main executable (default)"
	@echo "  debug      - Build with debug symbols and sanitizers"
	@echo "  release    - Build optimized release version"
	@echo "  static     - Build static executable"
	@echo "  test       - Build and run tests"
	@echo "  install    - Install to system (/usr/local/bin)"
	@echo "  uninstall  - Remove from system"
	@echo "  clean      - Remove build artifacts"
	@echo "  clean-all  - Remove all generated files"
	@echo "  format     - Format source code"
	@echo "  lint       - Lint source code with cppcheck"
	@echo "  check-deps - Verify build dependencies"
	@echo "  dist       - Create distribution archive"
	@echo "  help       - Show this help message"
	@echo ""
	@echo "Options:"
	@echo "  DEBUG=1    - Enable debug build (default: 0)"
	@echo "  STATIC=1   - Enable static linking (default: 0)"
	@echo "  VERBOSE=1  - Enable verbose output (default: 0)"
	@echo ""
	@echo "Examples:"
	@echo "  make                    # Build release version"
	@echo "  make debug              # Build debug version"
	@echo "  make DEBUG=1            # Alternative debug build"
	@echo "  make STATIC=1           # Build static executable"
	@echo "  make clean all          # Clean then build"