#ifndef INTEGRATION_API_H
#define INTEGRATION_API_H

// Integration APIs for Byvalver - Connect to external frameworks
// Like plumbing connections to other systems

#include <stdint.h>
#include <stddef.h>

// Metasploit integration
typedef struct {
    const char* host;
    int port;
    const char* api_token;
} metasploit_config_t;

int init_metasploit_integration(const metasploit_config_t* config);
int send_shellcode_to_metasploit(const uint8_t* shellcode, size_t size, const char* name);
void cleanup_metasploit_integration(void);

// Cobalt Strike integration
typedef struct {
    const char* teamserver_host;
    int teamserver_port;
    const char* username;
    const char* password;
} cobalt_strike_config_t;

int init_cobalt_strike_integration(const cobalt_strike_config_t* config);
int upload_shellcode_to_cobalt_strike(const uint8_t* shellcode, size_t size, const char* beacon_id);
void cleanup_cobalt_strike_integration(void);

// Generic framework integration
typedef struct {
    const char* framework_name;
    int (*init_func)(void* config);
    int (*upload_func)(const uint8_t* shellcode, size_t size, const char* identifier);
    void (*cleanup_func)(void);
} framework_integration_t;

int register_framework_integration(const framework_integration_t* integration);
int upload_to_framework(const char* framework_name, const uint8_t* shellcode, size_t size, const char* identifier);

#endif /* INTEGRATION_API_H */