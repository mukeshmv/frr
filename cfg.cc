#include <string>
#include <stdio.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <cassert>

std::string vtydir = "/run/frr/";

struct vclient_t {
    std::string name;
    int fd = -1;
    vclient_t(const char* n) : name(n) {};
};

/* Wrapper around strerror to handle case where it returns NULL. */
const char *safe_strerror(int errnum)
{
	const char *s = strerror(errnum);
	return (s != NULL) ? s : "Unknown error";
}

static int
vtysh_connect (vclient_t& vclient)
{
    int ret;
    int sock, len;
    struct sockaddr_un addr;
    struct stat s_stat;
    std::string path;

    path = vtydir + "/" + vclient.name + ".vty";

    /* Stat socket to see if we have permission to access it. */
    ret = stat(path.c_str(), &s_stat);
    if (ret < 0 && errno != ENOENT) {
        fprintf(stderr, "vtysh_connect(%s): stat = %s\n", path.c_str(),
                safe_strerror(errno));
        return -1;
    }

    if (ret >= 0) {
        if (!S_ISSOCK(s_stat.st_mode)) {
            fprintf(stderr, "vtysh_connect(%s): Not a socket\n",
                    path.c_str());
            return -1;
        }
    }

    sock = socket(AF_UNIX, SOCK_STREAM, 0);
    if (sock < 0) {
        fprintf(stderr, "vtysh_connect(%s): socket = %s\n", path.c_str(),
                safe_strerror(errno));
        return -1;
    }

    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, path.c_str(), sizeof(addr.sun_path));
    len = sizeof(addr.sun_family) + strlen(addr.sun_path);

    ret = connect(sock, (struct sockaddr *)&addr, len);
    if (ret < 0) {
        fprintf(stderr, "vtysh_connect(%s): connect = %s\n", path.c_str(),
                safe_strerror(errno));
        close(sock);
        return -1;
    }
    vclient.fd = sock;
    return 0;
}

static void
vtysh_close (vclient_t& vclient)
{
    close(vclient.fd);
    vclient.fd = -1;
}

static int
vtysh_execute (vclient_t& vclient, const std::string& cmd)
{
    printf("writing to fd %d\n", vclient.fd);
    int ret = write(vclient.fd, cmd.c_str(), cmd.length() + 1);
    if (ret <= 0) {
        printf("error writing to fd %d\n", vclient.fd);
        /* close connection and try to reconnect */
        fprintf(stderr, "vtysh_execute(%s): execute = %s failed %s retrying\n",
                vclient.name.c_str(), cmd.c_str(),
                safe_strerror(errno));
        vtysh_close(vclient);
        ret = vtysh_connect(vclient);
        if (ret < 0)
            return ret;
        /* retry line */
        ret = write(vclient.fd, cmd.c_str(), cmd.length() + 1);
        if (ret <= 0) {
            fprintf(stderr, "vtysh_execute(%s): execute = %s failed %s again\n",
                    vclient.name.c_str(), cmd.c_str(),
                    safe_strerror(errno));
            return ret;
        }
    }
    printf("finished writing %s to fd %d\n", cmd.c_str(), vclient.fd);
    return ret;
}
#define array_size(ar) (sizeof(ar) / sizeof(ar[0]))
static ssize_t vtysh_receive(const vclient_t& vclient, char *buf,
				    size_t bufsz, int *pass_fd)
{
	struct iovec iov[1] = {
		{
			.iov_base = buf,
			.iov_len = bufsz,
		},
	};
	union {
		uint8_t buf[CMSG_SPACE(sizeof(int))];
		struct cmsghdr align;
	} u;
	struct msghdr mh = {};
	mh.msg_iov = iov;
	mh.msg_iovlen = array_size(iov);
	mh.msg_control = u.buf;
	mh.msg_controllen = sizeof(u.buf);
	struct cmsghdr *cmh = CMSG_FIRSTHDR(&mh);
	ssize_t ret;

	cmh->cmsg_level = SOL_SOCKET;
	cmh->cmsg_type = SCM_RIGHTS;
	cmh->cmsg_len = CMSG_LEN(sizeof(int));
	memset(CMSG_DATA(cmh), -1, sizeof(int));

    printf("reading from fd %d buf %p bufsz %lu iovlen %lu\n",
           vclient.fd, buf, bufsz, mh.msg_iovlen);
	do {
		ret = recvmsg(vclient.fd, &mh, 0);
		if (ret >= 0 || (errno != EINTR && errno != EAGAIN))
			break;
	} while (true);

	if (cmh->cmsg_len == CMSG_LEN(sizeof(int))) {
		int fd;

		memcpy(&fd, CMSG_DATA(cmh), sizeof(int));
		if (fd != -1) {
			if (pass_fd)
				*pass_fd = fd;
			else
				close(fd);
		}
	}
	return ret;
}

static int
vtysh_read(const vclient_t& vclient)
{
	int ret;
    char stackbuf[4096];
    char *buf = stackbuf;
    size_t bufsz = sizeof(stackbuf);
    char *bufvalid, *end = NULL;
    char terminator[3] = {0, 0, 0};

    bufvalid = buf;
    do {
        ssize_t nread;

        nread = vtysh_receive(
            vclient, bufvalid, buf + bufsz - bufvalid - 1, nullptr);

        if (nread < 0 && (errno == EINTR || errno == EAGAIN))
            continue;

        if (nread <= 0) {
            fprintf(stderr,
                    "vtysh_read(): error reading from %s: %s (%d)\n",
                    vclient.name.c_str(), safe_strerror(errno), errno);
            break;
        }

        bufvalid += nread;

        /* Null terminate so we may pass this to *printf later. */
        bufvalid[0] = '\0';

        /*
         * We expect string output from daemons, so instead of looking
         * for the full 3 null bytes of the terminator, we check for
         * just one instead and assume it is the first byte of the
         * terminator. The presence of the full terminator is checked
         * later.
         */
        if (bufvalid - buf >= 4)
            end = (char*) memmem(bufvalid - 4, 4, "\0", 1);

        /*
         * calculate # bytes we have, up to & not including the
         * terminator if present
         */
        size_t textlen = (end ? end : bufvalid) - buf;
        bool b = false;

        /* feed line processing callback if present */
#if 0
        while (callback && bufvalid > buf && (end > buf || !end)) {
            textlen = (end ? end : bufvalid) - buf;
            char *eol = memchr(buf, '\n', textlen);
            if (eol)
                /* line break */
                *eol++ = '\0';
            else if (end == buf)
                /*
                 * no line break, end of input, no text left
                 * before end; nothing to write
                 */
                b = true;
            else if (end)
                /* no nl, end of input, but some text left */
                eol = end;
            else if (bufvalid == buf + bufsz - 1) {
                /*
                 * no nl, no end of input, no buffer space;
                 * realloc
                 */
                char *new_buf;

                bufsz *= 2;
                if (buf == stackbuf) {
                    new_buf = (char*) malloc(bufsz);
                    memcpy(new_buf, stackbuf, sizeof(stackbuf));
                } else
                    new_buf = (char*) realloc(buf, bufsz);

                bufvalid = bufvalid - buf + new_buf;
                buf = new_buf;
                /* if end != NULL, we won't be reading more
                 * data... */
                assert(end == NULL);
                b = true;
            } else
                b = true;

            if (b)
                break;

            /* eol is at line end now, either \n => \0 or \0\0\0 */
            assert(eol && eol <= bufvalid);

            fprintf(stdout, "%s\n", buf);

            /* shift back data and adjust bufvalid */
            memmove(buf, eol, bufvalid - eol);
            bufvalid -= eol - buf;
            if (end)
                end -= eol - buf;
        }
        /* else if no callback, dump raw */
        if (!callback) {
#else
            fprintf(stdout, "%s\n", buf);
            memmove(buf, buf + textlen, bufvalid - buf - textlen);
            bufvalid -= textlen;
            if (end)
                end -= textlen;

            /*
             * ----------------------------------------------------
             * At this point `buf` should be in one of two states:
             * - Empty (i.e. buf == bufvalid)
             * - Contains up to 4 bytes of the terminator
             * ----------------------------------------------------
             */
            assert(((buf == bufvalid)
                    || (bufvalid - buf <= 4 && buf[0] == 0x00)));
//        }
#endif

        /* if we have the terminator, break */
        if (end && bufvalid - buf == 4) {
            assert(!memcmp(buf, terminator, 3));
            ret = buf[3];
            break;
        }

    } while (true);

    if (buf != stackbuf)
        free(buf);
    return ret;
}

int main()
{
    vclient_t vclients[] = {
        "bgpd",
    };
    fprintf(stdout, "Connecting\n");
    for (auto& vclient: vclients) {
        if (vtysh_connect(vclient) != 0) {
            return -1;
        }
    }
    fprintf(stdout, "Start writing\n");

    vtysh_execute(vclients[0], "enable");
    vtysh_read(vclients[0]);
    vtysh_execute(vclients[0], "configure");
    vtysh_read(vclients[0]);
    vtysh_execute(vclients[0], "router bgp 100");
    vtysh_read(vclients[0]);
    vtysh_execute(vclients[0], "neighbor 10.0.0.4 remote-as 500");
    vtysh_read(vclients[0]);
    vtysh_execute(vclients[0], "end");
    vtysh_read(vclients[0]);
    fprintf(stdout, "Done config, Start show cmd\n");

    vtysh_execute(vclients[0], "show ip bgp summary json");
    vtysh_read(vclients[0]);

    return 0;
}
