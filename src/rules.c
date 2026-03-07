#include "../include/rules.h"
#include <arpa/inet.h> // for ntohl

void add_rule(rule_set_t *set, uint32_t ip, bool allow) {
    if (set->count < MAX_RULES) {
        set->rules[set->count].ip = ip;
        set->rules[set->count].allow = allow;
        set->count++;
    }
}

bool check_packet(rule_set_t *set, uint32_t ip) {
    for (int i = 0; i < set->count; i++) {
        if (set->rules[i].ip == ip) {
            return set->rules[i].allow;
        }
    }
    return true; // default allow
}