#ifndef RULES_H
#define RULES_H

#include <stdint.h>
#include <stdbool.h>

#define MAX_RULES 100

typedef struct {
    uint32_t ip;       // IP address in network byte order
    bool allow;        // true = allow, false = block
} ip_rule_t;

typedef struct {
    ip_rule_t rules[MAX_RULES];
    int count;
} rule_set_t;

void add_rule(rule_set_t *set, uint32_t ip, bool allow);
bool check_packet(rule_set_t *set, uint32_t ip);

#endif