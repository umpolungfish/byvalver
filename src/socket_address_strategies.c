/*
 * Socket Address Structure Null Handling Strategy
 *
 * PROBLEM: Network shellcode (bind/reverse shells) commonly uses IPv4 addresses
 * and port numbers that contain null bytes:
 * - IPv4 addresses: 127.0.0.1 (0x7F000001), 192.168.0.1 (0xC0A80001), 10.0.0.1 (0x0A000001)
 * - Low port numbers: 80 (0x0050), 443 (0x01BB) in network byte order
 * - Direct PUSH of these values introduces null bytes in shellcode
 *
 * SOLUTION: Three complementary strategies for null-free socket address construction:
 * A. XOR-Encoded IP Addresses - XOR encode addresses, decode at runtime
 * B. Byte-by-Byte IP Construction - Build addresses using shifts and OR operations
 * C. Port Number Encoding - Use XCHG for byte swapping low port numbers
 *
 * FREQUENCY: Critical for all network shellcode (bind shells, reverse shells, connect-back)
 * PRIORITY: 77-80 (High - essential for network operations)
 *
 * Example transformations:
 *   Original: PUSH 0x7F000001 (127.0.0.1) - contains nulls
 *   Strategy A: PUSH 0x7E010100; POP EAX; XOR EAX, 0x01010100; PUSH EAX
 *   Strategy B: XOR EAX,EAX; MOV AL,1; SHL EAX,24; OR AL,127; PUSH EAX
 *
 *   Original: PUSH WORD 0x0050 (port 80) - contains null
 *   Strategy C: XOR AX,AX; MOV AL,80; XCHG AL,AH; PUSH AX
 */

#include "strategy.h"
#include "utils.h"
#include <stdio.h>
#include <string.h>
#include <stdint.h>

/* ========================================================================
 * STRATEGY A: XOR-Encoded IP Addresses
 * ======================================================================== */

/*
 * Detect PUSH instructions with immediate values that look like IPv4 addresses
 * containing null bytes (common patterns: 127.0.0.1, 192.168.x.x, 10.0.0.x)
 */
int can_handle_xor_encoded_ip(cs_insn *insn) {
    // Only handle PUSH with 32-bit immediate
    if (insn->id != X86_INS_PUSH ||
        insn->detail->x86.op_count != 1) {
        return 0;
    }

    cs_x86_op *op = &insn->detail->x86.operands[0];

    if (op->type != X86_OP_IMM) {
        return 0;
    }

    uint32_t imm = (uint32_t)op->imm;

    // Check if immediate contains null bytes
    if (is_null_free(imm)) {
        return 0; // Already null-free
    }

    // Check if this looks like an IPv4 address pattern:
    // - Has at least one null octet
    // - Has at least one non-null octet in typical IP range (1-255)
    uint8_t octet0 = (imm >> 0) & 0xFF;
    uint8_t octet1 = (imm >> 8) & 0xFF;
    uint8_t octet2 = (imm >> 16) & 0xFF;
    uint8_t octet3 = (imm >> 24) & 0xFF;

    // Check for common network address patterns
    // - 127.0.0.x (loopback)
    // - 192.168.x.x (private class C)
    // - 10.0.0.x (private class A)
    // - x.x.0.x or x.0.x.x (any address with null octets)

    int has_null_octet = (octet0 == 0 || octet1 == 0 || octet2 == 0 || octet3 == 0);
    int has_valid_octet = (octet0 > 0 || octet1 > 0 || octet2 > 0 || octet3 > 0);

    // Must have both null and non-null octets to be an IP address candidate
    if (!has_null_octet || !has_valid_octet) {
        return 0;
    }

    // Additional pattern matching for common IP ranges
    if (octet3 == 127 && octet1 == 0 && octet2 == 0) { // 127.0.0.x
        return 1;
    }
    if (octet3 == 192 && octet2 == 168) { // 192.168.x.x
        return 1;
    }
    if (octet3 == 10 && octet1 == 0 && octet2 == 0) { // 10.0.0.x
        return 1;
    }
    if (octet3 == 172 && (octet2 >= 16 && octet2 <= 31)) { // 172.16-31.x.x
        return 1;
    }

    // Accept any address with null octets as potential IP address
    return has_null_octet;
}

/*
 * Calculate size for XOR-encoded IP address generation
 * Size: PUSH encoded (5) + POP EAX (1) + XOR EAX, key (5) + PUSH EAX (1) = 12 bytes
 */
size_t get_size_xor_encoded_ip(cs_insn *insn) {
    (void)insn; // Unused parameter
    return 12; // PUSH imm32 + POP EAX + XOR EAX, imm32 + PUSH EAX
}

/*
 * Find an XOR key that makes the IP address null-free
 * Strategy: XOR each null octet with 0x01, leave non-null octets as-is or XOR with 0x01
 * for consistency
 */
uint32_t find_ip_xor_key(uint32_t ip_addr) {
    uint32_t xor_key = 0;

    for (int i = 0; i < 4; i++) {
        uint8_t octet = (ip_addr >> (i * 8)) & 0xFF;
        if (octet == 0) {
            // XOR null octets with 0x01 to make them 0x01
            xor_key |= (0x01 << (i * 8));
        } else {
            // For consistency, XOR non-null octets with 0x01 too
            // This ensures the key itself is uniform and easy to encode
            xor_key |= (0x01 << (i * 8));
        }
    }

    return xor_key;
}

/*
 * Generate null-free code using XOR encoding for IP addresses
 */
void generate_xor_encoded_ip(struct buffer *b, cs_insn *insn) {
    cs_x86_op *op = &insn->detail->x86.operands[0];
    uint32_t ip_addr = (uint32_t)op->imm;

    // Find XOR key (typically 0x01010101 for most cases)
    uint32_t xor_key = find_ip_xor_key(ip_addr);
    uint32_t encoded_ip = ip_addr ^ xor_key;

    // PUSH encoded_ip (5 bytes: 68 + 4-byte immediate)
    buffer_write_byte(b, 0x68);
    buffer_write_dword(b, encoded_ip);

    // POP EAX (1 byte: 58)
    buffer_write_byte(b, 0x58);

    // XOR EAX, xor_key (5 bytes: 35 + 4-byte immediate)
    buffer_write_byte(b, 0x35);
    buffer_write_dword(b, xor_key);

    // PUSH EAX (1 byte: 50)
    buffer_write_byte(b, 0x50);
}

// Define Strategy A
strategy_t socket_xor_ip_strategy = {
    .name = "Socket XOR-Encoded IP Address Strategy",
    .can_handle = can_handle_xor_encoded_ip,
    .get_size = get_size_xor_encoded_ip,
    .generate = generate_xor_encoded_ip,
    .priority = 80  // High priority for network shellcode
};

/* ========================================================================
 * STRATEGY B: Byte-by-Byte IP Construction
 * ======================================================================== */

/*
 * Detect PUSH instructions with immediate values that are IPv4 addresses
 * This strategy is a fallback for IPs that XOR encoding doesn't handle well
 */
int can_handle_bytewise_ip(cs_insn *insn) {
    // Only handle PUSH with 32-bit immediate
    if (insn->id != X86_INS_PUSH ||
        insn->detail->x86.op_count != 1) {
        return 0;
    }

    cs_x86_op *op = &insn->detail->x86.operands[0];

    if (op->type != X86_OP_IMM) {
        return 0;
    }

    uint32_t imm = (uint32_t)op->imm;

    // Check if immediate contains null bytes
    if (is_null_free(imm)) {
        return 0; // Already null-free
    }

    // This strategy applies to the same addresses as XOR strategy
    // but with lower priority (fallback)
    uint8_t octet0 = (imm >> 0) & 0xFF;
    uint8_t octet1 = (imm >> 8) & 0xFF;
    uint8_t octet2 = (imm >> 16) & 0xFF;
    uint8_t octet3 = (imm >> 24) & 0xFF;

    int has_null_octet = (octet0 == 0 || octet1 == 0 || octet2 == 0 || octet3 == 0);
    int has_valid_octet = (octet0 > 0 || octet1 > 0 || octet2 > 0 || octet3 > 0);

    return has_null_octet && has_valid_octet;
}

/*
 * Calculate size for byte-by-byte IP construction
 * Worst case: XOR EAX,EAX (2) + multiple MOV/SHL/OR operations (2-6 bytes each)
 * Estimate: 2 + 4*3 = 14 bytes average
 */
size_t get_size_bytewise_ip(cs_insn *insn) {
    cs_x86_op *op = &insn->detail->x86.operands[0];
    uint32_t ip_addr = (uint32_t)op->imm;

    // Count non-zero octets
    int non_zero_count = 0;
    for (int i = 0; i < 4; i++) {
        if (((ip_addr >> (i * 8)) & 0xFF) != 0) {
            non_zero_count++;
        }
    }

    // XOR EAX,EAX (2) + operations for each non-zero octet (3-4 bytes) + PUSH EAX (1)
    return 2 + (non_zero_count * 4) + 1;
}

/*
 * Generate byte-by-byte IP address construction
 * Build the address in EAX using shifts and OR operations
 */
void generate_bytewise_ip(struct buffer *b, cs_insn *insn) {
    cs_x86_op *op = &insn->detail->x86.operands[0];
    uint32_t ip_addr = (uint32_t)op->imm;

    uint8_t octets[4];
    octets[0] = (ip_addr >> 0) & 0xFF;   // LSB (first octet in little-endian)
    octets[1] = (ip_addr >> 8) & 0xFF;
    octets[2] = (ip_addr >> 16) & 0xFF;
    octets[3] = (ip_addr >> 24) & 0xFF;  // MSB (last octet in little-endian)

    // XOR EAX, EAX - clear register (2 bytes: 31 C0)
    buffer_write_byte(b, 0x31);
    buffer_write_byte(b, 0xC0);

    // Build the IP address byte-by-byte from LSB to MSB
    // Strategy: Start with the last octet, shift, add next octet, repeat

    // Find the first (highest) non-zero octet to start with
    int start_idx = -1;
    for (int i = 3; i >= 0; i--) {
        if (octets[i] != 0) {
            start_idx = i;
            break;
        }
    }

    if (start_idx == -1) {
        // All octets are zero (shouldn't happen based on detection)
        // Just push zero
        buffer_write_byte(b, 0x50); // PUSH EAX
        return;
    }

    // Start with the highest non-zero octet
    if (octets[start_idx] != 0) {
        // MOV AL, octet (2 bytes: B0 + immediate)
        buffer_write_byte(b, 0xB0);
        buffer_write_byte(b, octets[start_idx]);
    }

    // Process remaining octets from high to low
    for (int i = start_idx - 1; i >= 0; i--) {
        // Shift left by 8 bits (3 bytes: C1 E0 08)
        buffer_write_byte(b, 0xC1);
        buffer_write_byte(b, 0xE0);
        buffer_write_byte(b, 0x08);

        if (octets[i] != 0) {
            // OR AL, octet (2 bytes: 0C + immediate)
            buffer_write_byte(b, 0x0C);
            buffer_write_byte(b, octets[i]);
        }
        // If octet is 0, we just shifted - no need to OR
    }

    // PUSH EAX (1 byte: 50)
    buffer_write_byte(b, 0x50);
}

// Define Strategy B
strategy_t socket_bytewise_ip_strategy = {
    .name = "Socket Byte-by-Byte IP Construction Strategy",
    .can_handle = can_handle_bytewise_ip,
    .get_size = get_size_bytewise_ip,
    .generate = generate_bytewise_ip,
    .priority = 78  // Slightly lower priority than XOR encoding
};

/* ========================================================================
 * STRATEGY C: Port Number Encoding
 * ======================================================================== */

/*
 * Detect PUSH instructions with 16-bit immediate values (ports) containing nulls
 * Port numbers < 256 create nulls in network byte order (big-endian)
 * e.g., port 80 = 0x0050 in network byte order
 */
int can_handle_port_encoding(cs_insn *insn) {
    // Handle PUSH with immediate that could be a port number
    if (insn->id != X86_INS_PUSH ||
        insn->detail->x86.op_count != 1) {
        return 0;
    }

    cs_x86_op *op = &insn->detail->x86.operands[0];

    if (op->type != X86_OP_IMM) {
        return 0;
    }

    // Check if this is a 16-bit immediate (port number range)
    // Ports are 0-65535, but in practice < 1024 are privileged
    // Focus on common ports: 80, 443, 8080, etc.
    int64_t imm = op->imm;

    if (imm < 0 || imm > 0xFFFF) {
        return 0; // Not a valid port number
    }

    uint16_t port = (uint16_t)imm;

    // In network byte order (big-endian), low ports have null high byte
    // Port 80 (0x0050) has null in high byte when represented as 16-bit value
    // Check if either byte is null
    uint8_t high_byte = (port >> 8) & 0xFF;
    uint8_t low_byte = port & 0xFF;

    if (high_byte == 0 || low_byte == 0) {
        // This port encoding will contain a null byte
        // Common examples: 80 (0x0050), 443 (0x01BB might be ok), 8080 (0x1F90)
        return 1;
    }

    return 0;
}

/*
 * Calculate size for port number encoding
 * Size: XOR AX,AX (3) + MOV AL,port (2) + XCHG AL,AH (2) + PUSH AX (2) = 9 bytes
 */
size_t get_size_port_encoding(cs_insn *insn) {
    (void)insn; // Unused parameter
    return 9; // XOR AX,AX + MOV AL,imm8 + XCHG AL,AH + PUSH AX
}

/*
 * Generate null-free port number encoding using byte swap
 * For low port numbers (< 256), use XCHG to swap bytes into network byte order
 */
void generate_port_encoding(struct buffer *b, cs_insn *insn) {
    cs_x86_op *op = &insn->detail->x86.operands[0];
    uint16_t port = (uint16_t)op->imm;

    uint8_t high_byte = (port >> 8) & 0xFF;
    uint8_t low_byte = port & 0xFF;

    // XOR AX, AX (3 bytes: 66 31 C0) - 16-bit register clear
    buffer_write_byte(b, 0x66);
    buffer_write_byte(b, 0x31);
    buffer_write_byte(b, 0xC0);

    if (low_byte == 0 && high_byte != 0) {
        // Port like 0x0100 (256) - high byte is set, low byte is null
        // MOV AH, high_byte (2 bytes: B4 + immediate)
        buffer_write_byte(b, 0xB4);
        buffer_write_byte(b, high_byte);
    } else if (high_byte == 0 && low_byte != 0) {
        // Port like 0x0050 (80) - low byte is set, high byte is null
        // MOV AL, low_byte (2 bytes: B0 + immediate)
        buffer_write_byte(b, 0xB0);
        buffer_write_byte(b, low_byte);

        // XCHG AL, AH (2 bytes: 86 C4) - swap bytes to network byte order
        buffer_write_byte(b, 0x86);
        buffer_write_byte(b, 0xC4);
    } else {
        // Both bytes are zero or both are non-zero
        // For both non-zero, construct byte by byte
        if (low_byte != 0) {
            buffer_write_byte(b, 0xB0); // MOV AL, low_byte
            buffer_write_byte(b, low_byte);
        }
        if (high_byte != 0) {
            buffer_write_byte(b, 0xB4); // MOV AH, high_byte
            buffer_write_byte(b, high_byte);
        }
    }

    // PUSH AX (2 bytes: 66 50) - push 16-bit value
    buffer_write_byte(b, 0x66);
    buffer_write_byte(b, 0x50);
}

// Define Strategy C
strategy_t socket_port_encoding_strategy = {
    .name = "Socket Port Number Encoding Strategy",
    .can_handle = can_handle_port_encoding,
    .get_size = get_size_port_encoding,
    .generate = generate_port_encoding,
    .priority = 77  // High priority for port numbers
};

/* ========================================================================
 * Registration Functions
 * ======================================================================== */

/*
 * Register all socket address handling strategies
 * Called from strategy_registry.c during initialization
 */
void register_socket_address_strategies() {
    register_strategy(&socket_xor_ip_strategy);      // Priority 80
    register_strategy(&socket_bytewise_ip_strategy); // Priority 78
    register_strategy(&socket_port_encoding_strategy); // Priority 77
}
