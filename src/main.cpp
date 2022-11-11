#include "1m-block.hpp"
#include <fstream>
#include <csignal>

using namespace std;

unordered_set<string> DB;

static struct nfq_handle *handle;
static struct nfq_q_handle *qh;

void InterruptHandler(const int signo);

bool setDB(const string& fileName);
bool queueingPacket();

int main(int argc, char* argv[]) {
    signal(SIGINT, InterruptHandler);
    signal(SIGTERM, InterruptHandler);

    string fileName;

    if(argc != 2) {
        cerr << "Error: Wrong parameters are given!\n";
        cerr << "syntax : 1m-block <site list file>\n";
        cerr << "sample : 1m-block top-1m.txt" << endl;

        return 1;
    }

    fileName = argv[1];
    if(not setDB(fileName)) return 1;

    if(not queueingPacket()) return 1;

    return 0;
}

/**
 * @brief Handle signal
 * 
 * @param signo 
 */
void InterruptHandler(const int signo) {
    if(signo == SIGINT or signo == SIGTERM) {
        if(signo == SIGINT) cout << "\nKeyboard Interrupt\n";
        else cout << "\nKeyboard Terminate\n";

        nfq_destroy_queue(qh);
        nfq_close(handle);

        exit(0);
    }
}

/**
 * @brief Set Database
 * 
 * @param fileName - File name for opening
 * @return true 
 * @return false 
 */
bool setDB(const string& fileName) {
    ifstream listFile;
    string hostName;

    size_t idx;

	listFile.open(fileName, fstream::in);
    if(listFile.fail()) {
        cerr << "Error: Error while open file\n";
        cerr << "Please check file name!" << endl;

        return false;
    }

    while(not listFile.eof()) {
        getline(listFile, hostName);

        idx = hostName.find(',');
        if(idx == string::npos) continue;

        hostName.erase(0, idx + 1);
        DB.insert(hostName);
    }

    listFile.close();

    return true;
}

/**
 * @brief Queueing packets
 * 
 * @return true
 * @return false
 */
bool queueingPacket() {
	int fd, rv;
	char buf[4096] __attribute__ ((aligned));

    cout << "opening library handle\n";
	handle = nfq_open();

    if (not handle) {
		cerr << "Error: error during nfq_open()" << endl;
		return false;
	}

	cout << "unbinding existing nf_queue handler for AF_INET (if any)\n";
	if (nfq_unbind_pf(handle, AF_INET) < 0) {
		cerr << "Error: error during nfq_unbind_pf()" << endl;
		return false;
	}

	cout << "binding nfnetlink_queue as nf_queue handler for AF_INET\n";
	if (nfq_bind_pf(handle, AF_INET) < 0) {
		cerr << "Error: error during nfq_bind_pf()" << endl;
		return false;
	}

	cout << "binding this socket to queue '0'\n";
	qh = nfq_create_queue(handle, 0, &cb, NULL);
	if (not qh) {
		cerr << "Error: error during nfq_create_queue()" << endl;
		return false;
	}

	cout << "setting copy_packet mode\n";
	if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
		cerr << "Error: can't set packet_copy mode" << endl;
		return false;
	}

	fd = nfq_fd(handle);

	while( true ) {
		if ((rv = recv(fd, buf, sizeof(buf), 0)) >= 0) {
#ifdef DEBUG
			cout << "[DEBUG] pkt received\n";
#endif
			nfq_handle_packet(handle, buf, rv);
			continue;
		}
		/* if your application is too slow to digest the packets that
		 * are sent from kernel-space, the socket buffer that we use
		 * to enqueue packets may fill up returning ENOBUFS. Depending
		 * on your application, this error may be ignored. nfq_nlmsg_verdict_putPlease, see
		 * the doxygen documentation of this library on how to improve
		 * this situation.
		 */
		if (rv < 0 and errno == ENOBUFS) {
			cout << "losing packets!\n";
			continue;
		}

		cerr << "recv failed";
		break;
	}

	cout << "unbinding from queue 0\n";
	nfq_destroy_queue(qh);

#ifdef INSANE
	/* normally, applications SHOULD NOT issue this command, since
	 * it detaches other programs/sockets from AF_INET, too ! */
	cout << "unbinding from AF_INET\n";
	nfq_unbind_pf(h, AF_INET);
#endif

	cout << "closing library handle\n";
	nfq_close(handle);

    return true;
}
