// vajractl - send a command to a Vajra agent.
//
//   vajractl <address> ping
//   vajractl <address> apply <module.so|module.dll>
//   vajractl <address> revert p1
//   vajractl <address> list
//
// <address> is the agent's socket path (Linux) or pipe name (Windows,
// \\.\pipe\<name>). Exit status: 0 on "ok", 1 on an error reply, 2 on a local
// failure (cannot connect, bad arguments).
// SPDX-License-Identifier: MIT
#include <cerrno>
#include <climits>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>

#if defined(_WIN32)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#else
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#endif

namespace {

bool absolute_path(const char* in, std::string& out) {
#if defined(_WIN32)
    char buf[MAX_PATH * 4];
    const DWORD n = ::GetFullPathNameA(in, sizeof buf, buf, nullptr);
    if (n == 0 || n >= sizeof buf) return false;
    if (::GetFileAttributesA(buf) == INVALID_FILE_ATTRIBUTES) return false;
    out = buf;
    return true;
#else
    char buf[PATH_MAX];
    if (!::realpath(in, buf)) return false;
    out = buf;
    return true;
#endif
}

#if defined(_WIN32)
int exchange(const char* address, const std::string& cmd, std::string& reply) {
    HANDLE h = INVALID_HANDLE_VALUE;
    for (int attempt = 0; attempt < 50; ++attempt) {
        h = ::CreateFileA(address, GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, 0, nullptr);
        if (h != INVALID_HANDLE_VALUE) break;
        if (::GetLastError() != ERROR_PIPE_BUSY) break;
        ::WaitNamedPipeA(address, 200);
    }
    if (h == INVALID_HANDLE_VALUE) {
        std::fprintf(stderr, "vajractl: cannot connect to %s (error %lu)\n", address,
                     static_cast<unsigned long>(::GetLastError()));
        return 2;
    }
    DWORD put = 0;
    if (!::WriteFile(h, cmd.data(), static_cast<DWORD>(cmd.size()), &put, nullptr) || put != cmd.size()) {
        std::fprintf(stderr, "vajractl: write failed\n");
        ::CloseHandle(h);
        return 2;
    }
    char buf[4096];
    DWORD got = 0;
    while (::ReadFile(h, buf, sizeof buf, &got, nullptr) && got > 0) reply.append(buf, got);
    ::CloseHandle(h);
    return 0;
}
#else
int exchange(const char* address, const std::string& cmd, std::string& reply) {
    struct sockaddr_un addr;
    std::memset(&addr, 0, sizeof addr);
    addr.sun_family = AF_UNIX;
    if (std::strlen(address) >= sizeof addr.sun_path) {
        std::fprintf(stderr, "vajractl: socket path too long\n");
        return 2;
    }
    std::strcpy(addr.sun_path, address);
    const int fd = ::socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd < 0 || ::connect(fd, reinterpret_cast<struct sockaddr*>(&addr), sizeof addr) != 0) {
        std::fprintf(stderr, "vajractl: cannot connect to %s: %s\n", address, std::strerror(errno));
        if (fd >= 0) ::close(fd);
        return 2;
    }
    std::size_t done = 0;
    while (done < cmd.size()) {
        const ssize_t n = ::write(fd, cmd.data() + done, cmd.size() - done);
        if (n <= 0) {
            std::fprintf(stderr, "vajractl: write failed\n");
            ::close(fd);
            return 2;
        }
        done += static_cast<std::size_t>(n);
    }
    char buf[4096];
    for (;;) {
        const ssize_t n = ::read(fd, buf, sizeof buf);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) break;
        reply.append(buf, static_cast<std::size_t>(n));
    }
    ::close(fd);
    return 0;
}
#endif

}  // namespace

int main(int argc, char** argv) {
    if (argc < 3) {
        std::fprintf(stderr, "usage: %s <socket|pipe> ping | list | apply <module> | revert <id>\n", argv[0]);
        return 2;
    }
    std::string cmd = argv[2];
    if (cmd == "apply" && argc >= 4) {
        std::string resolved;
        if (!absolute_path(argv[3], resolved)) {
            std::fprintf(stderr, "vajractl: %s: no such file\n", argv[3]);
            return 2;
        }
        cmd += " " + resolved;
    } else {
        for (int i = 3; i < argc; ++i) {
            cmd += " ";
            cmd += argv[i];
        }
    }
    cmd += "\n";
    std::string reply;
    if (const int rc = exchange(argv[1], cmd, reply); rc != 0) return rc;
    std::fputs(reply.c_str(), stdout);
    return reply.compare(0, 2, "ok") == 0 ? 0 : 1;
}
