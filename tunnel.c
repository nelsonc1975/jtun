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
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/aes.h>
#include <openssl/err.h>

#define PKGLEN 1500
#define BUFLEN (AES_BLOCK_SIZE + CBCLEN(PKGLEN) + AES_BLOCK_SIZE)
#define CBCLEN(l) (((l) + AES_BLOCK_SIZE) / AES_BLOCK_SIZE * AES_BLOCK_SIZE)
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

void usage(const char *name)
{
    fprintf(stderr,
            "Usage: %s [-46scv] [-d dev] [-h host] [-p port] "
            "[<host> <port>]\n",
            name);
    exit(1);
}

int main(int argc, char **argv)
{
    struct addrinfo hints;
    struct addrinfo *result;

    int dev, sock;
    union sa_t addr;
    socklen_t addrlen;
    struct ifreq ifr;

    const char *tun_device = "/dev/net/tun";

    int ip_family = AF_INET;
    int isserv = 1;
    const char *laddr = NULL;
    const char *lport = "";
    const char *rhost = NULL;
    const char *rport = NULL;
    const char *devname = "jtun%d";
    int verbose = 0;
    int fg = 0;

    int opt;
    while ((opt = getopt(argc, argv, "fv46scd:h:p:")) != -1) {
        switch (opt) {
            case '4':
                ip_family = AF_INET;
            case '6':
                ip_family = AF_INET6;
                break;
            case 's':
                isserv = 1;
                break;
            case 'c':
                isserv = 0;
                break;
            case 'h':
                laddr = strdup(optarg);
                break;
            case 'p':
                lport = strdup(optarg);
                break;
            case 'd':
                devname = strdup(optarg);
                break;
            case 'v':
                ++verbose;
                break;
            case 'f':
                fg = 1;
                break;
            default:
                usage(argv[0]);
                break;
        }
    }

    if (!isserv) {
        if (optind + 2 != argc) {
            usage(argv[0]);
        }

        rhost = argv[optind];
        rport = argv[optind + 1];
    }
    else {
        if (optind != argc) {
            usage(argv[0]);
        }
    }

    if ((dev = open(tun_device, O_RDWR)) < 0) {
        perror("Open TUN device failed");
        exit(2);
    }

    bzero(&ifr, sizeof(ifr));
    ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
    if (devname != NULL) {
        strncpy(ifr.ifr_name, devname, IFNAMSIZ);
    }
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

    int isbind = 0;
    while (result != NULL) {
        memcpy(&addr.a, result -> ai_addr, result -> ai_addrlen);
        addrlen = result -> ai_addrlen;
        if (bind(sock, &addr.a, addrlen) == 0) {
            isbind = 1;
            break;
        }
        else if (verbose >= 2) {
            perror("bind failed, try next");
        }
        result = result -> ai_next;
    }

    if (!isbind) {
        fprintf(stderr, "cannot bind local address\n");
        exit(7);
    }

    freeaddrinfo(result);

    addrlen = MAXADDRLEN;
    if (getsockname(sock, &addr.a, &addrlen) == -1) {
        perror("getsockname failed");
        exit(8);
    }

    char host[100];
    char serv[50];
    int res = getnameinfo(&addr.a, addrlen, host, sizeof(host),
            serv, sizeof(serv), NI_NUMERICHOST | NI_NUMERICSERV);
    if (res != 0) {
        fprintf(stderr,
                "cannot get name from address: %s\n", gai_strerror(res));
    }

    if (!isserv) {
        if (getaddrinfo(rhost, rport, &hints, &result)) {
            perror("getaddrinfo for remote address failed");
            exit(9);
        }
        if (!result) {
            fprintf(stderr, "getaddrinfo for remote returned nothing\n");
            exit(10);
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

    if (!fg) {
        char logfname[IFNAMSIZ + 20];
        snprintf(logfname, sizeof(logfname), "jtun.%s.log", ifr.ifr_name);
        int logfd = open(logfname, O_WRONLY | O_CREAT | O_TRUNC,
                S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
        if (logfd == -1) {
            perror("cannot create log file");
            exit(16);
        }
        int nullfd = open("/dev/null", O_RDWR);
        if (nullfd == -1) {
            perror("cannot create null file");
            exit(17);
        }

        struct passwd * jtun = getpwnam("jtun");
        if (jtun == NULL) {
            perror("getpwnam for jtun error");
            exit(18);
        }

        pid_t pid;
        if ((pid = fork()) != 0) {
            printf("TUN: %s\n", ifr.ifr_name);
            if (isserv) {
                printf("Bind: %s:%s\n", host, serv);
            }

            char pidfname[IFNAMSIZ + 20];
            snprintf(pidfname, sizeof(pidfname), "jtun.%s.pid", ifr.ifr_name);
            FILE *pidfile = fopen(pidfname, "w");
            if (keyfile == NULL) {
                perror("cannot create pid file");
                exit(15);
            }
            fprintf(pidfile, "%d", pid);
            fclose(pidfile);
            return 0;
        }

        close(STDIN_FILENO);
        close(STDOUT_FILENO);
        close(STDERR_FILENO);
        dup2(nullfd, STDOUT_FILENO);
        dup2(logfd, STDOUT_FILENO);
        dup2(logfd, STDERR_FILENO);
        close(logfd);
        close(nullfd);

        setgid(jtun -> pw_gid);
        setuid(jtun -> pw_uid);
    }

    printf("JTun started.\n");
    fflush(stdout);

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int maxfd = (sock > dev) ? sock : dev;
    while (1) {
        uint8_t tbuf[PKGLEN];
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
            ssize_t cnt = read(dev, (void *)tbuf, PKGLEN);
            if (verbose >= 4) {
                fputs("t>", stdout); dumphex(tbuf, cnt);
            }
            RAND_bytes(sbuf, AES_BLOCK_SIZE);
            EVP_CIPHER_CTX_reset(ctx);
            EVP_EncryptInit(ctx, EVP_aes_128_cbc(), key, sbuf);
            int lenc, lenc2;
            EVP_EncryptUpdate(ctx, &sbuf[AES_BLOCK_SIZE], &lenc, tbuf, cnt);
            EVP_EncryptFinal(ctx, &sbuf[AES_BLOCK_SIZE + lenc], &lenc2);
            lenc += (lenc2 + AES_BLOCK_SIZE);
            if (RAND_bytes(&sbuf[lenc], AES_BLOCK_SIZE) == 1) {
                ssize_t padlen = sbuf[lenc + AES_BLOCK_SIZE - 1] % AES_BLOCK_SIZE;
                lenc += padlen;
            }
            sendto(sock, &sbuf, lenc, 0, &addr.a, addrlen);
            res = getnameinfo(&addr.a, addrlen, host, sizeof(host),
                    serv, sizeof(serv), NI_NUMERICHOST | NI_NUMERICSERV);
            if (verbose >= 4) {
                fputs("==", stdout); dumphex(sbuf, lenc);
            }
            if (res == 0) {
                if (verbose >= 4) {
                    printf("s<%s:%s\n", host, serv);
                }
            }
            else {
                if (verbose >= 4) {
                    puts("s<...");
                }
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
                if (verbose >= 4) {
                    printf("s>%s:%s\n", host, serv);
                }
            }
            else {
                if (verbose >= 4) {
                    puts("s>...");
                }
            }
            if (verbose >= 4) {
                fputs("==", stdout); dumphex(sbuf, cnt);
            }

            int frompeer = 0;
            if (!isserv) {
                if (addrlen == fromlen &&
                        memcmp(&from.a, &addr.a, fromlen) == 0) {
                    frompeer = 1;
                }
                else if (verbose >= 2) {
                    char mhost[100];
                    char mserv[20];
                    getnameinfo(&from.a, fromlen, host, sizeof(host),
                            serv, sizeof(serv),
                            NI_NUMERICHOST | NI_NUMERICSERV);
                    getnameinfo(&addr.a, addrlen, mhost, sizeof(mhost),
                            mserv, sizeof(mserv),
                            NI_NUMERICHOST | NI_NUMERICSERV);
                    fprintf(stderr, "Addr mismatch: from(%s:%s) addr(%s:%s)\n",
                            host, serv, mhost, mserv);
                }
            }
            else {
                memcpy(&addr.a, &from.a, fromlen);
                addrlen = fromlen;
                frompeer = 1;
            }

            if (frompeer) {
                cnt = (cnt / AES_BLOCK_SIZE) * AES_BLOCK_SIZE;
                int ldec, ldec2;
                EVP_CIPHER_CTX_reset(ctx);
                EVP_DecryptInit(ctx, EVP_aes_128_cbc(), key, sbuf);
                EVP_DecryptUpdate(ctx, tbuf, &ldec, &sbuf[AES_BLOCK_SIZE], cnt);
                EVP_DecryptFinal(ctx, &tbuf[ldec], &ldec2);
                ldec += ldec2;
                if (verbose >= 4) {
                    fputs("t<", stdout); dumphex(tbuf, ldec);
                }
                write(dev, (void *)tbuf, ldec);
            }
        }
    }
    EVP_CIPHER_CTX_free(ctx);

    return 0;
}
