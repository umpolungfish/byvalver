CC = gcc
CFLAGS = -Wall -Wextra -pedantic

SRC_DIR = src
BIN_DIR = bin

TARGET = byvalver

# Explicitly list source files to exclude byvalver.c which is now refactored
SRCS = $(SRC_DIR)/main.c $(SRC_DIR)/core.c $(SRC_DIR)/utils.c $(SRC_DIR)/strategy_registry.c $(SRC_DIR)/mov_strategies.c $(SRC_DIR)/arithmetic_strategies.c $(SRC_DIR)/memory_strategies.c $(SRC_DIR)/jump_strategies.c $(SRC_DIR)/general_strategies.c $(SRC_DIR)/hash_utils.c $(SRC_DIR)/anti_debug_strategies.c $(SRC_DIR)/shift_strategy.c $(SRC_DIR)/peb_strategies.c
OBJS = $(patsubst $(SRC_DIR)/%.c, $(BIN_DIR)/%.o, $(SRCS))

LDFLAGS = -lcapstone

# Debug build: make DEBUG=1
ifdef DEBUG
CFLAGS += -DDEBUG -g
endif

all: decoder.h $(BIN_DIR)/$(TARGET)

decoder.bin: decoder.asm
	nasm -f bin -o $@ $<

decoder.h: decoder.bin
	xxd -i $< > $@

$(BIN_DIR)/$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

$(BIN_DIR)/%.o: $(SRC_DIR)/%.c decoder.h
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	rm -rf $(BIN_DIR)/* decoder.bin decoder.h
