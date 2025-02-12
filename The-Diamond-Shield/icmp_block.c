#include <sys/param.h>
#include <sys/module.h>
#include <sys/kernel.h>
#include <sys/socket.h>
#include <sys/mbuf.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <net/pfil.h>

static unsigned int icmp_dropped = 0;
static unsigned int total_dropped_size = 0;

// Packet filter hook function
static pfil_return_t icmp_block_hook(pfil_packet_t pkt, struct ifnet *ifp, int dir, void *arg, struct inpcb *inp) {
    struct mbuf *m = *(pkt.m);  // Correctly dereference to get the mbuf

    if (m == NULL) return PFIL_PASS;  // Allow packet if invalid
    if (dir != PFIL_IN) return PFIL_PASS;  // Only filter incoming packets

    struct ip *ip_hdr = mtod(m, struct ip *);
    if (ip_hdr->ip_p == IPPROTO_ICMP) {
        struct icmp *icmp_hdr = (struct icmp *)(ip_hdr + 1);

        if (icmp_hdr->icmp_type == ICMP_ECHO) {  // Block ICMP Echo Requests
            icmp_dropped++;
            total_dropped_size += ntohs(ip_hdr->ip_len);

            printf("ICMP Echo Request blocked. Total dropped: %u, Total size: %u bytes\n",
                   icmp_dropped, total_dropped_size);
            return PFIL_DROPPED;  // Drop the packet
        }
    }
    return PFIL_PASS;  // Allow other packets
}

static struct pfil_hook *icmp_hook;

static int load_handler(module_t mod, int event_type, void *arg) {
    struct pfil_hook_args pha;

    switch (event_type) {
        case MOD_LOAD:
            pha.pa_version = PFIL_VERSION;
            pha.pa_flags = PFIL_IN;
            pha.pa_func = icmp_block_hook;
            pha.pa_type = PFIL_TYPE_IP4;
            pha.pa_modname = "icmp_block_mod";
            pha.pa_rulname = "icmp_block_rule";

            icmp_hook = pfil_add_hook(&pha);  // Register the hook
            if (icmp_hook != NULL) {
                printf("ICMP Block Module loaded successfully.\n");
            } else {
                printf("Failed to register ICMP block hook.\n");
                return EFAULT;
            }
            break;

        case MOD_UNLOAD:
            if (icmp_hook != NULL) {
                pfil_remove_hook(icmp_hook);
                printf("ICMP Block Module unloaded.\n");
            }
            break;

        default:
            return EOPNOTSUPP;
    }
    return 0;
}

static moduledata_t icmp_block_mod = {
    "icmp_block",          // Module name
    load_handler,          // Event handler
    NULL                   // Extra data
};

DECLARE_MODULE(icmp_block, icmp_block_mod, SI_SUB_DRIVERS, SI_ORDER_MIDDLE);