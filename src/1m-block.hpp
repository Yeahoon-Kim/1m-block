#pragma once

#include <iostream>
#include <iomanip>
#include <cstdint>
#include <cstring>
#include <unordered_set>

#include <netinet/in.h>
#include <linux/types.h>
#include <linux/netfilter.h>		/* for NF_ACCEPT */
#include <errno.h>

#include <libnetfilter_queue/libnetfilter_queue.h>

#include "ipv4hdr.hpp"
#include "tcphdr.hpp"

#define FILTER_ALERT "Alert: This packet is filtered! :)\n"

extern std::unordered_set<std::string> DB;

#ifdef DEBUG
uint32_t print_pkt(struct nfq_data *tb);
#endif

int acceptPacket(struct nfq_q_handle *qh, const uint32_t id);
int dropPacket(struct nfq_q_handle *qh, const uint32_t id);

bool parseHTTP(std::string payload);

int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg, struct nfq_data *nfa, void *data);
