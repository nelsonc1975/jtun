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
#include <pwd.h>
#include <openssl/aes.h>
#include <openssl/rand.h>

#define PKGLEN 1500
#define HEADLEN 6
#define MSGLEN (PKGLEN + HEADLEN)
#define BUFLEN CBCLEN(MSGLEN)
#define CBCLEN(l) (((l) + AES_BLOCK_SIZE - 1) / AES_BLOCK_SIZE * AES_BLOCK_SIZE)
#define MAXADDRLEN sizeof(struct sockaddr_in6)

union sa_t {
    struct sockaddr a;
    uint8_t _buf[MAXADDRLEN];
};

const char HEX[] = {
    '0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
    'A', 'B', 'C', 'D', 'E', 'F'
};

void dumphex(const uint8_t *data, ssize_t count)
{
    char * text = malloc(count * 2 + 1);
    for (ssize_t i = 0; i < count; ++ i) {
        uint8_t byte = data[i];
        text[2 * i] = HEX[byte >> 4];
        text[2 * i + 1] = HEX[byte & 15];
    }
    text[2 * count] = '\0';
    puts(text);
}

int main(int argc, const char **argv)
{
    struct addrinfo hints;
    struct addrinfo *result;

    int dev, sock;
    union sa_t addr;
    socklen_t addrlen;
    struct ifreq ifr;

    const char *tun_device = "/dev/net/tun";

    if (argc < 3) {
        fprintf(stderr, "Usage: %s [-6] <localip> <localport> "
                "[<remotehost> <remoteport>]\n", argv[0]);
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
    printf("TUN: %s\n", ifr.ifr_name);

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
        fprintf(stderr,
                "getaddrinfo for local returned multiple addresses\n");
    }
    memcpy(&addr.a, result -> ai_addr, result -> ai_addrlen);
    addrlen = result -> ai_addrlen;

    if (bind(sock, &addr.a, addrlen)) {
        perror("bind to local address failed");
        exit(7);
    }

    freeaddrinfo(result);

    addrlen = MAXADDRLEN;
    if (getsockname(sock, &addr.a, &addrlen) == -1) {
        perror("getsockname failed");
        exit(8);
    }

    char host[100];
    char serv[20];
    int res = getnameinfo(&addr.a, addrlen, host, sizeof(host),
            serv, sizeof(serv), NI_NUMERICHOST | NI_NUMERICSERV);
    if (res != 0) {
        fprintf(stderr,
                "Cannot get name from address: %s\n", gai_strerror(res));
    }
    else {
        printf("Bound to %s:%s\n", host, serv);
    }

    if (!autoaddress) {
        if (getaddrinfo(rhost, rport, &hints, &result)) {
            perror("getaddrinfo for remote address failed");
            exit(9);
        }
        if (!result) {
            fprintf(stderr, "getaddrinfo for remote returned nothing\n");
            exit(10);
        }
        if (result -> ai_next) {
            fprintf(stderr, "getaddrinfo for remote returned "
                    "multiple addresses\n");
        }
        memcpy(&addr.a, result -> ai_addr, result -> ai_addrlen);
        addrlen = result -> ai_addrlen;
        freeaddrinfo(result);
    }

    fcntl(sock, F_SETFL, O_NONBLOCK);
    fcntl(dev, F_SETFL, O_NONBLOCK);

    uint8_t key[16];  /* 128 bits key */
    FILE *keyfile = fopen("key", "rb");
    if (keyfile == NULL) {
        perror("cannot open key file");
        exit(11);
    }
    if (fread(key, sizeof(key), 1, keyfile) != 1) {
        fprintf(stderr, "error read key\n");
        exit(12);
    }
    fclose(keyfile);

    uint8_t iv[AES_BLOCK_SIZE];
    FILE *ivfile = fopen("iv", "rb");
    if (keyfile == NULL) {
        perror("cannot open iv file");
        exit(13);
    }
    if (fread(iv, sizeof(iv), 1, ivfile) != 1) {
        fprintf(stderr, "error read iv\n");
        exit(14);
    }
    fclose(ivfile);
    uint8_t ivc[AES_BLOCK_SIZE];  /* copy of iv */

    AES_KEY enc_key, dec_key;
    AES_set_encrypt_key(key, sizeof(key) * 8, &enc_key);
    AES_set_decrypt_key(key, sizeof(key) * 8, &dec_key);

    pid_t pid;
    if ((pid = fork()) != 0) {
        FILE *pidfile = fopen("jtun.pid", "w");
        if (keyfile == NULL) {
            perror("cannot open jtun.pid");
            exit(15);
        }
        fprintf(pidfile, "%d", pid);
        fclose(pidfile);
        return 0;
    }

    struct passwd * jtun = getpwnam("jtun");
    if (jtun == NULL) {
        perror("getpwnam for jtun error");
        exit(15);
    }

    setgid(jtun -> pw_gid);
    setuid(jtun -> pw_uid);

    int maxfd = (sock > dev) ? sock : dev;
    while (1) {
        uint8_t tbuf[BUFLEN];
        uint8_t sbuf[BUFLEN];

        fd_set rfds;
        FD_ZERO(&rfds);
        FD_SET(sock, &rfds);
        FD_SET(dev, &rfds);

        int ret = select(maxfd + 1, &rfds, NULL, NULL, NULL);
        if (ret < 0) {
            continue;
        }

        if (FD_ISSET(dev, &rfds)) {
            ssize_t cnt = read(dev, (void *)&tbuf[HEADLEN], BUFLEN);
            *((uint16_t *)tbuf) = htons((uint16_t)cnt);
            if (RAND_bytes(&tbuf[2], 4) != 1) {
                *((uint32_t *)&tbuf[2]) = 0xAA5555AA;
            }
            // fputs("t>", stdout); dumphex(tbuf, cnt + HEADLEN);
            memcpy(ivc, iv, AES_BLOCK_SIZE);
            AES_cbc_encrypt(tbuf, sbuf, cnt + HEADLEN, &enc_key, ivc, AES_ENCRYPT);
            ssize_t slen = CBCLEN(cnt + HEADLEN);
            if (RAND_bytes(&sbuf[slen], AES_BLOCK_SIZE) == 1) {
                uint8_t padlen = sbuf[slen + AES_BLOCK_SIZE - 1] % AES_BLOCK_SIZE;
                slen += padlen;
            }
            sendto(sock, &sbuf, slen, 0, &addr.a, addrlen);
            res = getnameinfo(&addr.a, addrlen, host, sizeof(host),
                    serv, sizeof(serv), NI_NUMERICHOST | NI_NUMERICSERV);
            // fputs("==", stdout); dumphex(sbuf, slen);
            if (res == 0) {
                // printf("s<%s:%s\n", host, serv);
            }
            else {
                // puts("s<...");
            }
        }

        if (FD_ISSET(sock, &rfds)) {
            union sa_t from;
            socklen_t fromlen = MAXADDRLEN;

            ssize_t cnt = recvfrom(sock, &sbuf, sizeof(sbuf), 0,
                    &from.a, &fromlen);
            res = getnameinfo(&from.a, fromlen, host, sizeof(host),
                    serv, sizeof(serv), NI_NUMERICHOST | NI_NUMERICSERV);
            if (res == 0) {
                // printf("s>%s:%s\n", host, serv);
            }
            else {
                // puts("s>...");
            }
            // fputs("==", stdout); dumphex(sbuf, cnt);

            int address_ok = 0;
            if (!autoaddress) {
                if (addrlen == fromlen &&
                        memcmp(&from.a, &addr.a, fromlen) == 0) {
                    address_ok = 1;
                }
                else {
                    char host2[100];
                    char serv2[20];
                    getnameinfo(&from.a, fromlen, host, sizeof(host),
                            serv, sizeof(serv),
                            NI_NUMERICHOST | NI_NUMERICSERV);
                    getnameinfo(&addr.a, addrlen, host2, sizeof(host2),
                            serv2, sizeof(serv2),
                            NI_NUMERICHOST | NI_NUMERICSERV);
                    fprintf(stderr, "Addr mismatch: from(%s:%s) addr(%s:%s)\n",
                            host, serv, host2, serv2);
                }
            }
            else {
                memcpy(&addr.a, &from.a, fromlen);
                addrlen = fromlen;
                address_ok = 1;
            }

            if (address_ok) {
                cnt = (cnt / AES_BLOCK_SIZE) * AES_BLOCK_SIZE;
                memcpy(ivc, iv, AES_BLOCK_SIZE);
                AES_cbc_encrypt(sbuf, tbuf, cnt, &dec_key, ivc, AES_DECRYPT);
                uint8_t msglen = ntohs(*(uint16_t *)tbuf);
                // fputs("t<", stdout); dumphex(tbuf, msglen + HEADLEN);
                write(dev, (void *)&tbuf[HEADLEN], msglen);
            }
        }
    }

    return 0;
}
