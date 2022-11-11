#include "1m-block.hpp"

#ifdef DEBUG
/**
 * @brief Print packet information.
 * 
 * @param tb 
 * @return uint32_t 
 */
uint32_t print_pkt(struct nfq_data *tb) {
	struct nfqnl_msg_packet_hdr *ph;
	struct nfqnl_msg_packet_hw *hwph;
	uint32_t id, mark, ifi;
	uint8_t *data;
	int ret;

	ph = nfq_get_msg_packet_hdr(tb);
	if (ph) {
		id = ntohl(ph->packet_id);

		std::cout << "hw_protocol: 0x" << std::hex << std::setw(4) << std::setfill('0') << ntohs(ph->hw_protocol);
		std::cout << " hook: " << (unsigned int)ph->hook;
		std::cout << " id: " << (unsigned int)id << '\n';
	}
	else {
		std::cerr << "Error: Error while getting message packet header" << std::endl;
		return -1;
	}

	hwph = nfq_get_packet_hw(tb);
	if (hwph) {
		int i, hlen = ntohs(hwph->hw_addrlen);

		// Print hardware address of source device
		std::cout << "hw_src_addr: ";
		for (i = 0; i < hlen - 1; i++) std::cout << std::hex << std::setw(2) << std::setfill('0') << (unsigned int)hwph->hw_addr[i] << ':';
		std::cout << std::hex << std::setw(2) << std::setfill('0') << (unsigned int)hwph->hw_addr[hlen - 1] << '\n';
	}

	// Print packet mark
	mark = nfq_get_nfmark(tb);
	if(mark) std::cout << "mark: " << std::dec << (unsigned int)mark << '\n';

	// Print the interface that the packet was received through
	ifi = nfq_get_indev(tb);
	if(ifi) std::cout << "indev: " << std::dec << (unsigned int)ifi << '\n';

	// Print gets the interface that the packet will be routed out
	ifi = nfq_get_outdev(tb);
	if(ifi) std::cout << "outdev: " << std::dec << (unsigned int)ifi << '\n';

	// Print the physical interface that the packet was received
	ifi = nfq_get_physindev(tb);
	if(ifi) std::cout << "physindev: " << std::dec << (unsigned int)ifi << '\n';

	// Print the physical interface that the packet output
	ifi = nfq_get_physoutdev(tb);
	if(ifi) std::cout << "physoutdev: " << std::dec << (unsigned int)ifi << '\n';

	// Print payload
	ret = nfq_get_payload(tb, &data);
	if (ret >= 0) std::cout << "Payload length: " << std::dec << ret << '\n';
	
	std::cout << '\n';

	return id;
}
#endif

/**
 * @brief Accept packet.
 * Accept packet and return value.
 * 
 * @param qh 
 * @param id 
 * @return int 
 */
int acceptPacket(struct nfq_q_handle *qh, const uint32_t id) {
	return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
}

/**
 * @brief Drop packet.
 * Drop packet and return value.
 * 
 * @param qh 
 * @param id 
 * @return int 
 */
int dropPacket(struct nfq_q_handle *qh, const uint32_t id) {
	return nfq_set_verdict(qh, id, NF_DROP, 0, NULL);
}

/**
 * @brief parse payload and filtering.
 * 
 * @param payload 
 * @return true 
 * @return false 
 */
bool parseHTTP(std::string payload) {
	const std::string delimiter = "\r\n", fieldName = "Host: ";
	std::string field, hostValue;
	std::size_t idx;

	idx = payload.find(delimiter);
	while(idx != std::string::npos) {
		// Check each field
		field = payload.substr(0, idx);

		// Check Host Field
		if(field.find(fieldName) != std::string::npos) {
            hostValue = field.substr(fieldName.size(), field.size() - delimiter.size());

			if(DB.find(hostValue) != DB.end()) return true;
			else return false;
		}

		payload.erase(0, idx + delimiter.size());
		idx = payload.find(delimiter);
	}

	return false;
}

/**
 * @brief Check packet and filtering.
 * Check packet if it uses TCP, HTTP packet.
 * If a packet uses HTTP protocol, check its HOST field.
 * If a packet uses HTTPS protocol, check.
 * 
 * @param qh 
 * @param nfmsg 
 * @param nfa 
 * @param data 
 * @return int 
 */
int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg, struct nfq_data *nfa, void *data) {
	struct nfqnl_msg_packet_hdr *ph;
	int totalHeaderLength, packetLength, IPHeaderLength;
	uint8_t* packet;
	uint32_t id;

	std::string payload;

	TcpHdr* TCPHeader;
	IPv4Hdr* IPv4Header;

#ifdef DEBUG
	id = print_pkt(nfa);
	if(not id) return -1;
#else
	ph = nfq_get_msg_packet_hdr(nfa);
	id = ntohl(ph->packet_id);
	if(not id) return -1;
#endif

	if(nfq_get_payload(nfa, &packet) >= 0) {
		IPv4Header = (IPv4Hdr*)packet;                                  // Cast IP packet

		// Check if next layer protocol is TCP
		if(IPv4Header->ip_p != IPv4Hdr::IP_PROTOCOL::TCP) return acceptPacket(qh, id);
		
		packetLength = IPv4Header->totalLength();                       // Check total size of IP packet
		IPHeaderLength = IPv4Header->ip_hl << 2;                        // Check size of IP header
		TCPHeader = (TcpHdr*)(packet + IPHeaderLength);                 // Cast TCP segment

		// Check if source or destination port is using HTTP protocol
		if(TCPHeader->dport() != 80 and TCPHeader->sport() != 80) return acceptPacket(qh, id);

		totalHeaderLength = IPHeaderLength + (TCPHeader->th_off << 2);  // Check total size of TCP/IP header

		// Check if payload is empty
		if(packetLength == totalHeaderLength) return acceptPacket(qh, id);
		payload = (char*)(packet + totalHeaderLength);                  // Cast payload

		// Check if payload include filter keyword
		if(not parseHTTP(payload)) return acceptPacket(qh, id);
		else {
			std::cout << FILTER_ALERT;
			return dropPacket(qh, id);
		}
	}

	return -1;
}
