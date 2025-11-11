# BYVALVER Design Documentation

## Architecture Overview

BYVALVER follows a modular architecture using the strategy pattern to provide a clean, extensible framework for null-byte shellcode elimination. The system is designed with clear separation of concerns and maintainable code organization.

## Core Architecture Components

### 1. Core Engine (src/core.c/src/core.h)
The core engine contains the main processing logic that:
- Disassembles input shellcode using Capstone
- Analyzes instruction nodes for null bytes
- Coordinates the strategy selection process
- Handles offset recalculation for relative jumps/calls
- Generates the final null-free shellcode

### 2. Strategy Registry (src/strategy_registry.c/src/strategy.h)
The strategy registry manages:
- Global collection of available replacement strategies
- Priority-based selection of strategies
- Registration and retrieval of applicable strategies for instructions
- Strategy sorting and ranking

### 3. Utility Functions (src/utils.c/src/utils.h)
The utilities module provides:
- Common helper functions used by all strategies
- Low-level operations for building replacement instruction sequences
- Buffer management functions
- Register indexing and utility functions

### 4. Strategy Modules
Specialized modules for different instruction categories:

#### MOV Strategies (src/mov_strategies.c)
- Handles MOV instructions with immediate values
- Implements MOV-specific replacement strategies (arithmetic, shift, NEG, XOR encodings)
- Priority-based strategy selection for MOV operations

#### Arithmetic Strategies (src/arithmetic_strategies.c)
- Handles ADD, SUB, AND, OR, XOR, CMP operations with immediate values
- Implements arithmetic-specific replacement techniques
- Supports complex arithmetic equivalent constructions

#### Memory Strategies (src/memory_strategies.c)
- Handles memory access instructions (MOV from/to memory, LEA, etc.)
- Implements strategies for direct memory addressing that contains null bytes
- Supports complex memory access patterns

#### Jump Strategies (src/jump_strategies.c)
- Handles CALL and JMP instructions with immediate addresses
- Implements relative jump offset recalculation
- Supports conditional jump transformations

#### General Strategies (src/general_strategies.c)
- Handles general instructions like PUSH
- Implements common replacement patterns
- Supports PUSH imm8 vs PUSH imm32 optimizations

## Strategy Pattern Implementation

### Strategy Interface (strategy_t)
Each strategy implements the same interface:
```c
typedef struct {
    const char* name;                           // Strategy name for identification
    int (*can_handle)(cs_insn *insn);          // Function to check if strategy can handle instruction
    size_t (*get_size)(cs_insn *insn);         // Function to calculate new size
    void (*generate)(struct buffer *b, cs_insn *insn);  // Function to generate new code
    int priority;                              // Priority for strategy selection
} strategy_t;
```

### Strategy Selection Process
1. All registered strategies are evaluated against each instruction
2. Strategies that can handle the instruction are collected
3. Strategies are sorted by priority (highest first)
4. The highest-priority applicable strategy is used for replacement

### Registration System
Strategies are registered through dedicated functions:
- `register_mov_strategies()`
- `register_arithmetic_strategies()`
- `register_memory_strategies()`
- `register_jump_strategies()`
- `register_general_strategies()`

These are called during initialization to populate the global strategy registry.

## Build System

The Makefile has been updated to:
- Compile all modular source files
- Link the executable with the new architecture
- Avoid duplicate definition errors
- Ensure clean compilation without warnings

## Extensibility

The architecture supports easy addition of new strategies:
1. Create a new function implementing the strategy interface
2. Register the strategy in the appropriate module
3. The system automatically incorporates it into the selection process

## Memory Management

The system uses:
- Dynamic buffer allocation for shellcode output
- Proper cleanup of instruction nodes
- Efficient memory usage during processing

## Error Handling

The system includes:
- Proper Capstone library error handling
- Graceful degradation when strategies fail
- Validation of instruction handling

## Performance Considerations

The modular design maintains performance through:
- Efficient strategy lookup and sorting
- Minimal overhead in the main processing loop
- Optimized buffer management

---
---
```
                         BYVALVER ARCHITECTURE OVERVIEW
                         =============================      
                              [INPUT SHELLCODE]
                                     |
                                     |
                                     v
                         +-----------------------------+
                         |        CORE ENGINE          |
                         |  (src/core.c/src/core.h)    |
                         |                             |
                         | - Disassemble with Capstone |
                         | - Analyze for null bytes    |
                         | - Coordinate strategy sel.  |
                         | - Offset recalculation      |
                         | - Generate final shellcode  |
                         +--------------+--------------+
                                        |
                                        v
                         +-----------------------------+
                         |    STRATEGY REGISTRY        |
                         |(src/strategy_registry.c/h)  |
                         |                             |
                         | - Global strategy collection|
                         | - Priority-based selection  |
                         | - Strategy registration     |
                         | - Strategy ranking          |
                         +--------------+--------------+
                                        |
                                        v
                         +-----------------------------+
                         |     STRATEGY SELECTION      |
                         |       PROCESS FLOW          |
                         |                             |
                         | 1. Evaluate all strategies  |
                         | 2. Collect applicable ones  |
                         | 3. Sort by priority         |
                         | 4. Use highest priority     |
                         +--------------+--------------+
                                        |
                                        v
               +-----------------------+-----------------------+
               |                       |                       |
               v                       v                       v
         +-------------+        +-----------------+     +------------------+
         |MOV STRAT.   |        |ARITHMETIC STRAT |     |JUMP STRATEGIES   |
         |(mov_strat*) |        |(arithmetic_str*)|     |(jump_strategies) |
         +-------------+        +-----------------+     +------------------+
         | - MOV imm   |        | - ADD, SUB, AND |     | - CALL, JMP      |
         | - Arithmetic|        | - Complex equiv |     | - Rel. offset    |
         | - NEG, XOR  |        | - XOR, OR, CMP  |     | - Cond. jumps    |
         +-------------+        +-----------------+     +------------------+
               |                       |                       |
               v                       v                       v
         +-------------+        +------------------+    +------------------+
         |MEMORY STR   |        |GENERAL STRATEGIES|    |OTHER STRATEGIES  |
         |(memory_str*)|        |(general_strat*)  |    |                  |
         +-------------+        +------------------+    +------------------+
         | - Memory    |        | - PUSH, etc.     |    | (Extensible)     |
         | - Direct    |        | - imm8/imm32 opt |    |                  |
         | - Complex   |        | - Common repl.   |    |                  |
         +-------------+        +------------------+    +------------------+
    
                               STRATEGY INTERFACE
                               ==================
         +--------------------------------------------------------------+
         | strategy_t:                                                  |
         | - const char* name     // Strategy name                      |
         | - int (*can_handle)()  // Check if handles instruction       |
         | - size_t (*get_size)() // Calculate new size                 |
         | - void (*generate)()   // Generate replacement code          |
         | - int priority         // Strategy priority                  |
         +--------------------------------------------------------------+
    
                                 UTILITY FUNCTIONS
                                 =================
         +--------------------------------------------------------------+
         | src/utils.c/src/utils.h:                                     |
         | - Helper functions for all strategies                        |
         | - Low-level operations for instruction building              |
         | - Buffer management functions                                |
         | - Register indexing and utilities                            |
         +--------------------------------------------------------------+
    
                                  BUILD SYSTEM
                                  ============
         +--------------------------------------------------------------+
         | Makefile:                                                    |
         | - Compiles modular source files                              |
         | - Links executable with new architecture                     |
         | - Avoids duplicate definition errors                         |
         | - Ensures clean compilation without warnings                 |
         +--------------------------------------------------------------+
    
                                  EXTENSIBILITY
                                  =============
         +--------------------------------------------------------------+
         | Adding New Strategies:                                       |
         | 1. Create function implementing strategy interface           |
         | 2. Register strategy in appropriate module                   |
         | 3. System automatically incorporates into selection process  |
         +--------------------------------------------------------------+
```

```mmd
---
config:
  theme: neo-dark
  layout: elk
---
flowchart LR
    A["INPUT SHELLCODE"] --> B["CORE ENGINE
    <br>src/core.c/src/core.h<br>- Disassemble with Capstone<br>- Analyze for null bytes<br>- Coordinate strategy selection<br>- Offset recalculation<br>- Generate final shellcode"]
    B --> C["STRATEGY REGISTRY
    <br>src/strategy_registry.c/h<br>- Global strategy collection<br>- Priority-based selection<br>- Strategy registration<br>- Strategy ranking"]
    C --> D["STRATEGY SELECTION PROCESS
    <br>1. Evaluate all strategies<br>2. Collect applicable ones<br>3. Sort by priority<br>4. Use highest priority"]
    D --> E["MOV STRATEGIES
    <br>mov_strat*<br>- MOV imm<br>- Arithmetic<br>- NEG, XOR"] & F["ARITHMETIC STRATEGIES
    <br>arithmetic_str*<br>- ADD, SUB, AND<br>- Complex equivalents<br>- XOR, OR, CMP"] & G["JUMP STRATEGIES
    <br>jump_strategies<br>- CALL, JMP<br>- Relative offset<br>- Conditional jumps"]
    E --> H["MEMORY STRATEGIES
    <br>memory_str*<br>- Memory operations<br>- Direct access<br>- Complex patterns"]
    F --> I["GENERAL STRATEGIES
    <br>general_strat*<br>- PUSH, etc.<br>- imm8/imm32 optimization<br>- Common replacements"]
    G --> J["OTHER STRATEGIES
    <br>Extensible category"]
    E -.-> K["STRATEGY INTERFACE
    <br>strategy_t structure<br>- const char* name<br>- int can_handle function<br>- size_t get_size function<br>- void generate function<br>- int priority"] & L["UTILITY FUNCTIONS
    <br>src/utils.c/src/utils.h<br>- Helper functions<br>- Low-level operations<br>- Buffer management<br>- Register indexing"] & M["BUILD SYSTEM
    <br>Makefile<br>- Compiles modular source<br>- Links executable<br>- Avoids duplicate errors<br>- Clean compilation"] & N["EXTENSIBILITY
    <br>Adding New Strategies<br>1. Implement strategy interface<br>2. Register in module<br>3. Auto-incorporation"]
    F -.-> K & L & M & N
    G -.-> K & L & M & N
    H -.-> K & L & M & N
    I -.-> K & L & M & N
    J -.-> K & L & M & N
    C -.-> K & M
    B -.-> L & M
    K -.-> O["OUTPUT SHELLCODE"]
    L -.-> O
    M -.-> O
    N -.-> O
```