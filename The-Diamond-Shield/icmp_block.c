#include <sys/param.h>
#include <sys/module.h>
#include <sys/kernel.h>
#include <sys/socket.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <net/pfil.h>
#include <sys/mbuf.h>

static struct pfil_head *custom_pfil_head = NULL;

/* Register a PFIL head */
static int register_custom_pfil_head(void) {
    struct pfil_head_args pha = {
        .pa_version = PFIL_VERSION,
        .pa_flags = PFIL_IN | PFIL_OUT,
        .pa_type = PFIL_TYPE_IP4,
        .pa_name = "custom_ipv4_head"
    };

    custom_pfil_head = pfil_head_register(&pha);
    if (custom_pfil_head == NULL) {
        printf("Failed to register custom PFIL head.\n");
        return EFAULT;
    }

    printf("Custom PFIL head registered.\n");
    return 0;
}

static unsigned int icmp_dropped = 0;

static pfil_return_t icmp_block_hook(pfil_packet_t pkt, struct ifnet *ifp, int dir,
                                     void *arg, struct inpcb *inp) {
    struct mbuf *m = pkt.m ? *(pkt.m) : NULL;
    if (!m || dir != PFIL_IN) return PFIL_PASS;

    struct ip *ip_hdr = mtod(m, struct ip *);
    if (ip_hdr->ip_p == IPPROTO_ICMP) {
        struct icmp *icmp_hdr = (struct icmp *)(ip_hdr + 1);
        if (icmp_hdr->icmp_type == ICMP_ECHO) {
            icmp_dropped++;
            printf("ICMP Echo Request blocked. Total blocked: %u\n", icmp_dropped);
            return PFIL_DROPPED;
        }
    }
    return PFIL_PASS;
}

static struct pfil_hook *icmp_hook = NULL;

static int attach_icmp_hook(void) {
    if (!custom_pfil_head) return EINVAL;  // Ensure head is registered

    struct pfil_hook_args pha = {
        .pa_version = PFIL_VERSION,
        .pa_flags = PFIL_IN,
        .pa_type = PFIL_TYPE_IP4,
        .pa_func = icmp_block_hook,
        .pa_modname = "icmp_block_mod",
        .pa_rulname = "icmp_block_rule"
    };

    icmp_hook = pfil_add_hook(&pha);
    if (icmp_hook == NULL) {
        printf("Failed to attach ICMP block hook.\n");
        return EFAULT;
    }

    printf("ICMP block hook attached.\n");
    return 0;
}

static int module_handler(module_t mod, int event, void *arg) {
    int error = 0;

    switch (event) {
        case MOD_LOAD:
            error = register_custom_pfil_head();
            if (error) break;

            error = attach_icmp_hook();
            if (error) {
                pfil_head_unregister(custom_pfil_head);
                custom_pfil_head = NULL;
            }
            break;

        case MOD_UNLOAD:
            if (icmp_hook) {
                pfil_remove_hook(icmp_hook);
                printf("ICMP block hook removed.\n");
            }
            if (custom_pfil_head) {
                pfil_head_unregister(custom_pfil_head);
                printf("Custom PFIL head unregistered.\n");
            }
            break;

        default:
            error = EOPNOTSUPP;
    }

    return error;
}

static moduledata_t icmp_block_mod = {
    "icmp_block",      // Module name
    module_handler,      // Event handler
    NULL               // Extra data
};

DECLARE_MODULE(icmp_block, icmp_block_mod, SI_SUB_DRIVERS, SI_ORDER_MIDDLE);