#include <errno.h>
#include <linux/can.h>
#include <linux/can/isotp.h>
#include <net/if.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#define TP_MTU 4095

#define SEND_COMPLETE(fd) write(fd, "\x7f\x8c\x25\xab\xb6\x16\x1e\x94", 8)

int main(void)
{
    int fd = socket(AF_CAN, SOCK_DGRAM, CAN_ISOTP);
    if (fd < 0) {
        fprintf(stderr, "[!] error: Failed to open server socket -- %s\n", strerror(errno));
        return 1;
    }
    struct can_isotp_fc_options fcopts = { .bs = 16, .stmin = 5, .wftmax = 0 };
    if (setsockopt(fd, SOL_CAN_ISOTP, CAN_ISOTP_RECV_FC, &fcopts, sizeof(fcopts)) < 0) {
        fprintf(stderr, "[!] error: Failed to set socket options -- %s\n", strerror(errno));
        return 1;
    }

    struct ifreq ifr;
    strcpy(ifr.ifr_name, "vcan0");
    ioctl(fd, SIOCGIFINDEX, &ifr);

    struct sockaddr_can addr;
    memset(&addr, 0, sizeof(addr));
    addr.can_family = AF_CAN;
    addr.can_addr.tp.rx_id = 0x7e0;
    addr.can_addr.tp.tx_id = 0x7e8;
    addr.can_ifindex = ifr.ifr_ifindex;
    if (bind(fd, (struct sockaddr*) &addr, sizeof(addr)) < 0) {
        fprintf(stderr, "[!] error: Failed to bind server socket -- %s\n", strerror(errno));
        return 1;
    }

    dup2(fd, 0);
    dup2(fd, 1);
    dup2(fd, 2);

    char data[TP_MTU + 1];
    while (1) {
        ssize_t size = read(0, data, TP_MTU);
        if (size < 0) {
            fprintf(stderr, "[!] error: Failed to read user data -- %s\n", strerror(errno));
            continue;
        }
        if (size < 1) {
            continue;
        }
        data[size] = '\0';
        system(data);
        SEND_COMPLETE(fd);
    }

    return 1;
}
