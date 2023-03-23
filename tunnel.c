#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <netdb.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <linux/if_tun.h>
#include <net/if.h>

#define BUFLEN 1536
#define MAXADDRLEN sizeof(struct sockaddr_in6)

union sa_t {
    struct sockaddr a;
    uint8_t _buf[MAXADDRLEN];
};

int main(int argc, const char **argv)
{
    struct addrinfo hints;
    struct addrinfo *result, *rp;

    int dev, sock;
    unsigned char buf[BUFLEN];
    union sa_t addr;
    socklen_t addrlen;
    struct ifreq ifr;

    const char *tun_device = "/dev/net/tun";
    char dev_name[IFNAMSIZ + 1];

    if (argc < 3) {
        fprintf(stderr, "Usage: %s [-6] <localip> <localport> [<remotehost> <remoteport>]\n");
        exit(1);
    }

    int ip_family;
    if (strcmp(argv[1], "-6") == 0) {
        ++ argv;
        ip_family = AF_INET6;
    }
    else {
        ip_family = AF_INET;
    }

    int autoaddress = 1;
    const char *laddr = argv[1];
    const char *lport = argv[2];
    const char *rhost = NULL;
    const char *rport = NULL;

    if (argc == 5) {
        autoaddress = 0;
        rhost = argv[3];
        rport = argv[4];
    }

    if ((dev = open(tun_device, O_RDWR)) < 0) {
        perror("Open TUN device failed");
        exit(2);
    }

    bzero(&ifr, sizeof(ifr));
    ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
    if (ioctl(dev, TUNSETIFF, (void *)&ifr) < 0) {
        perror("ioctl(TUNSETIFF) failed");
        exit(3);
    }

    if ((sock = socket(ip_family, SOCK_DGRAM, 0)) == -1) {
        perror("Create socket failed");
        exit(4);
    }

    bzero(&hints, sizeof(struct addrinfo));
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_family = ip_family;

    if (getaddrinfo(laddr, lport, &hints, &result) != 0) {
        perror("getaddrinfo for local address failed");
        exit(5);
    }
    if (!result) {
        fprintf(stderr, "getaddrinfo for local returned nothing\n");
        exit(6);
    }
    if (result -> ai_next) {
        fprintf(stderr, "getaddrinfo for local returned multiple addresses\n");
    }
    memcpy(&addr.a, result -> ai_addr, result -> ai_addrlen);
    addrlen = result -> ai_addrlen;

    if (bind(sock, &addr.a, addrlen)) {
        perror("bind to local address failed");
        exit(7);
    }

    freeaddrinfo(result);

    if (!autoaddress) {
        if (getaddrinfo(rhost, rport, &hints, &result)) {
            perror("getaddrinfo for remote address failed");
            exit(8);
        }
        if (!result) {
            fprintf(stderr, "getaddrinfo for remote returned nothing\n");
            exit(9);
        }
        if (result -> ai_next) {
            fprintf(stderr, "getaddrinfo for remote returned multiple addresses\n");
        }
        memcpy(&addr.a, result -> ai_addr, result -> ai_addrlen);
        addrlen = result -> ai_addrlen;
        freeaddrinfo(result);
    }

    fcntl(sock, F_SETFL, O_NONBLOCK);
    fcntl(dev, F_SETFL, O_NONBLOCK);
    
    int maxfd = (sock > dev) ? sock : dev;
    while (1) {
        fd_set rfds;
        FD_ZERO(&rfds);
        FD_SET(sock, &rfds);
        FD_SET(dev, &rfds);

        int ret = select(maxfd + 1, &rfds, NULL, NULL, NULL);
        if (ret < 0) {
            continue;
        }

        if (FD_ISSET(dev, &rfds)) {
            ssize_t cnt = read(dev, (void *)&buf, sizeof(buf));
            sendto(sock, &buf, cnt, 0, &addr.a, addrlen);
        }

        if (FD_ISSET(sock, &rfds)) {
            union sa_t from;
            socklen_t fromlen = MAXADDRLEN;

            ssize_t cnt = recvfrom(sock, &buf, sizeof(buf), 0, &from.a, &fromlen);

            int address_ok = 0;
            if (!autoaddress) {
                if (addrlen == fromlen && memcmp(&from.a, &addr.a, fromlen) == 0) {
                    address_ok = 1;
                }
            }
            else {
                memcpy(&addr.a, &from.a, fromlen);
                addrlen = fromlen;
                address_ok = 1;
            }

            if (address_ok) {
                write(dev, (void *)&buf, cnt);
            }
        }
    }

    return 0;
}
