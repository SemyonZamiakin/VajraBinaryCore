// vajractl - send a command to a Vajra agent socket.
//
//   vajractl <socket> ping
//   vajractl <socket> apply /abs/path/patch.so
//   vajractl <socket> revert p1
//   vajractl <socket> list
// SPDX-License-Identifier: MIT
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include <cerrno>
#include <climits>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>

int main(int argc, char** argv) {
    if (argc < 3) {
        std::fprintf(stderr, "usage: %s <socket> ping | list | apply <module.so> | revert <id>\n", argv[0]);
        return 2;
    }
    std::string cmd = argv[2];
    if (cmd == "apply" && argc >= 4) {
        char resolved[PATH_MAX];
        if (!::realpath(argv[3], resolved)) {
            std::fprintf(stderr, "vajractl: %s: %s\n", argv[3], std::strerror(errno));
            return 2;
        }
        cmd += " ";
        cmd += resolved;
    } else {
        for (int i = 3; i < argc; ++i) {
            cmd += " ";
            cmd += argv[i];
        }
    }
    cmd += "\n";

    struct sockaddr_un addr;
    std::memset(&addr, 0, sizeof addr);
    addr.sun_family = AF_UNIX;
    if (std::strlen(argv[1]) >= sizeof addr.sun_path) {
        std::fprintf(stderr, "vajractl: socket path too long\n");
        return 2;
    }
    std::strcpy(addr.sun_path, argv[1]);
    const int fd = ::socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd < 0 || ::connect(fd, reinterpret_cast<struct sockaddr*>(&addr), sizeof addr) != 0) {
        std::fprintf(stderr, "vajractl: cannot connect to %s: %s\n", argv[1], std::strerror(errno));
        return 2;
    }
    std::size_t done = 0;
    while (done < cmd.size()) {
        const ssize_t n = ::write(fd, cmd.data() + done, cmd.size() - done);
        if (n <= 0) {
            std::fprintf(stderr, "vajractl: write failed\n");
            return 2;
        }
        done += static_cast<std::size_t>(n);
    }
    std::string reply;
    char buf[4096];
    for (;;) {
        const ssize_t n = ::read(fd, buf, sizeof buf);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) break;
        reply.append(buf, static_cast<std::size_t>(n));
    }
    ::close(fd);
    std::fputs(reply.c_str(), stdout);
    return reply.compare(0, 2, "ok") == 0 ? 0 : 1;
}
