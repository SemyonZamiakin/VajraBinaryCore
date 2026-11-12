// Vajra Binary Core - in-process patch agent.
// SPDX-License-Identifier: MIT
#include "vajra/agent.hpp"

#include <dlfcn.h>
#include <fcntl.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

#include <cerrno>
#include <cstring>
#include <mutex>
#include <sstream>
#include <thread>
#include <deque>
#include <vector>

#ifndef VAJRA_VERSION_STRING
#define VAJRA_VERSION_STRING "0.0.0"
#endif

namespace vajra {

const char* version() noexcept { return VAJRA_VERSION_STRING; }

struct Agent::Impl {
    Options opts;
    int listen_fd = -1;
    int wake_pipe[2] = {-1, -1};
    std::thread thread;
    bool running = false;

    struct Entry {
        std::string id;
        std::string module;
        Patch patch;
    };
    mutable std::mutex mu;  // guards entries / next_id
    std::deque<Entry> entries;  // deque: references stay valid on push_back
    unsigned next_id = 1;
};

Agent::Agent() : impl_(std::make_unique<Impl>()) {}

Agent::~Agent() { stop(); }

namespace {

bool read_line(int fd, std::string& line, int timeout_ms) {
    line.clear();
    char c;
    while (line.size() < 4096) {
        struct pollfd p{fd, POLLIN, 0};
        const int pr = ::poll(&p, 1, timeout_ms);
        if (pr <= 0) return false;
        const ssize_t n = ::read(fd, &c, 1);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) return !line.empty();
        if (c == '\n') return true;
        if (c != '\r') line.push_back(c);
    }
    return false;
}

void write_all(int fd, const std::string& s) {
    std::size_t done = 0;
    while (done < s.size()) {
        const ssize_t n = ::send(fd, s.data() + done, s.size() - done, MSG_NOSIGNAL);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) return;
        done += static_cast<std::size_t>(n);
    }
}

}  // namespace

Result Agent::start(const Options& options) {
    if (impl_->running) return {Status::AlreadyApplied, "agent is already running"};
    if (options.socket_path.empty()) return {Status::InvalidArgument, "socket path is empty"};
    struct sockaddr_un addr;
    std::memset(&addr, 0, sizeof addr);
    addr.sun_family = AF_UNIX;
    if (options.socket_path.size() >= sizeof addr.sun_path) return {Status::InvalidArgument, "socket path is too long"};
    std::memcpy(addr.sun_path, options.socket_path.c_str(), options.socket_path.size() + 1);

    // Replace a stale socket we own; refuse anything else at that path.
    struct stat st;
    if (::lstat(options.socket_path.c_str(), &st) == 0) {
        if (!S_ISSOCK(st.st_mode) || st.st_uid != ::geteuid())
            return {Status::PermissionDenied, "socket path exists and is not our socket"};
        ::unlink(options.socket_path.c_str());
    }

    const int fd = ::socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd < 0) return {Status::IoError, std::string("socket: ") + std::strerror(errno)};
    const mode_t old_mask = ::umask(0077);
    const int br = ::bind(fd, reinterpret_cast<struct sockaddr*>(&addr), sizeof addr);
    ::umask(old_mask);
    if (br != 0) {
        const int e = errno;
        ::close(fd);
        return {Status::IoError, std::string("bind: ") + std::strerror(e)};
    }
    ::chmod(options.socket_path.c_str(), 0600);
    if (::listen(fd, 4) != 0) {
        const int e = errno;
        ::close(fd);
        ::unlink(options.socket_path.c_str());
        return {Status::IoError, std::string("listen: ") + std::strerror(e)};
    }
    if (::pipe2(impl_->wake_pipe, O_CLOEXEC) != 0) {
        ::close(fd);
        ::unlink(options.socket_path.c_str());
        return {Status::IoError, "pipe2 failed"};
    }
    impl_->opts = options;
    impl_->listen_fd = fd;
    impl_->running = true;
    impl_->thread = std::thread([this] {
        for (;;) {
            struct pollfd p[2] = {{impl_->listen_fd, POLLIN, 0}, {impl_->wake_pipe[0], POLLIN, 0}};
            const int pr = ::poll(p, 2, -1);
            if (pr < 0) {
                if (errno == EINTR) continue;
                break;
            }
            if (p[1].revents) break;
            if (!(p[0].revents & POLLIN)) continue;
            const int c = ::accept4(impl_->listen_fd, nullptr, nullptr, SOCK_CLOEXEC);
            if (c < 0) continue;
            struct ucred cred;
            socklen_t len = sizeof cred;
            if (::getsockopt(c, SOL_SOCKET, SO_PEERCRED, &cred, &len) != 0 || cred.uid != ::geteuid()) {
                write_all(c, "error permission denied: peer is a different user\n");
                ::close(c);
                continue;
            }
            std::string line;
            if (read_line(c, line, 5000)) write_all(c, handle_command(line));
            ::close(c);
        }
    });
    return Result::ok();
}

void Agent::stop() {
    if (!impl_->running) return;
    const char b = 1;
    (void)!::write(impl_->wake_pipe[1], &b, 1);
    impl_->thread.join();
    ::close(impl_->listen_fd);
    ::close(impl_->wake_pipe[0]);
    ::close(impl_->wake_pipe[1]);
    ::unlink(impl_->opts.socket_path.c_str());
    impl_->listen_fd = -1;
    impl_->running = false;
}

Result Agent::apply_module(const std::string& path, std::string* id, std::string* message) {
    const int fd = ::open(path.c_str(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) return {Status::NotFound, "cannot open " + path + ": " + std::strerror(errno)};
    struct stat st;
    if (::fstat(fd, &st) != 0 || !S_ISREG(st.st_mode)) {
        ::close(fd);
        return {Status::InvalidArgument, path + " is not a regular file"};
    }
    if (impl_->opts.check_module_owner) {
        if (st.st_uid != ::geteuid() && st.st_uid != 0) {
            ::close(fd);
            return {Status::PermissionDenied, path + " is owned by another user"};
        }
        if (st.st_mode & (S_IWGRP | S_IWOTH)) {
            ::close(fd);
            return {Status::PermissionDenied, path + " is writable by group or others"};
        }
    }
    // Load through the descriptor we checked, not the path (no TOCTOU).
    const std::string fd_path = "/proc/self/fd/" + std::to_string(fd);
    void* handle = ::dlopen(fd_path.c_str(), RTLD_NOW | RTLD_LOCAL);
    ::close(fd);
    if (!handle) {
        const char* e = ::dlerror();
        return {Status::InvalidArgument, std::string("dlopen failed: ") + (e ? e : "?")};
    }
    auto entry = reinterpret_cast<PatchEntryFn>(::dlsym(handle, "vajra_patch_entry"));
    if (!entry) return {Status::NotFound, path + " does not export vajra_patch_entry"};

    Transaction tx(impl_->opts.patch);
    PatchContext ctx;
    ctx.heap = impl_->opts.heap;
    ctx.user = impl_->opts.user;
    ctx.tx = &tx;
    const int rc = entry(&ctx);
    if (message) *message = ctx.message;
    if (rc != 0)
        return {Status::InvalidArgument, "module declined to build a patch (" + std::to_string(rc) + ")" +
                                             (ctx.message.empty() ? "" : ": " + ctx.message)};
    Patch patch;
    if (Result r = tx.commit(&patch); !r) return r;

    std::lock_guard<std::mutex> g(impl_->mu);
    Impl::Entry e;
    e.id = "p" + std::to_string(impl_->next_id++);
    e.module = path;
    e.patch = std::move(patch);
    if (id) *id = e.id;
    impl_->entries.push_back(std::move(e));
    return Result::ok();
}

Result Agent::revert(const std::string& id) {
    Patch* p = nullptr;
    {
        std::lock_guard<std::mutex> g(impl_->mu);
        for (auto& e : impl_->entries)
            if (e.id == id) p = &e.patch;
    }
    if (!p) return {Status::NotFound, "no patch " + id};
    return p->revert(impl_->opts.patch);  // entries are never erased; deque keeps p valid
}

std::string Agent::list() const {
    std::lock_guard<std::mutex> g(impl_->mu);
    std::ostringstream os;
    for (const auto& e : impl_->entries)
        os << e.id << ' ' << (e.patch.active() ? "active" : "reverted") << ' ' << e.module << '\n';
    return os.str();
}

std::string Agent::handle_command(const std::string& line) {
    std::istringstream is(line);
    std::string cmd;
    is >> cmd;
    std::string arg;
    std::getline(is >> std::ws, arg);
    if (cmd == "ping") return std::string("ok vajra ") + version() + "\n";
    if (cmd == "list") return "ok\n" + list();
    if (cmd == "apply" && !arg.empty()) {
        std::string id, message;
        Result r = apply_module(arg, &id, &message);
        if (!r) return "error " + r.to_string() + "\n";
        return "ok " + id + (message.empty() ? "" : " " + message) + "\n";
    }
    if (cmd == "revert" && !arg.empty()) {
        Result r = revert(arg);
        if (!r) return "error " + r.to_string() + "\n";
        return "ok\n";
    }
    return "error unknown command (expected: ping | list | apply <module> | revert <id>)\n";
}

}  // namespace vajra
