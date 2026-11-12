// Vajra Binary Core - in-process patch agent.
//
// Linux:   Unix domain socket, mode 0600, peer uid checked with SO_PEERCRED;
//          modules are opened with O_NOFOLLOW, checked (owner, permissions)
//          and loaded through /proc/self/fd/N, so the checked file is the
//          loaded file.
// Windows: named pipe created with FILE_FLAG_FIRST_PIPE_INSTANCE (no name
//          squatting), PIPE_REJECT_REMOTE_CLIENTS, and a DACL that grants
//          access to the current user only; modules are checked (owner) and
//          held open without write sharing while LoadLibrary maps them.
// SPDX-License-Identifier: MIT
#include "vajra/agent.hpp"

#include <cerrno>
#include <cstring>
#include <deque>
#include <mutex>
#include <sstream>
#include <thread>
#include <vector>

#if defined(_WIN32)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <aclapi.h>
#include <sddl.h>
#else
#include <dlfcn.h>
#include <fcntl.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>
#endif

#ifndef VAJRA_VERSION_STRING
#define VAJRA_VERSION_STRING "0.0.0"
#endif

namespace vajra {

const char* version() noexcept { return VAJRA_VERSION_STRING; }

struct Agent::Impl {
    Options opts;
    std::thread thread;
    bool running = false;
#if defined(_WIN32)
    HANDLE pipe = INVALID_HANDLE_VALUE;
    HANDLE stop_event = nullptr;
#else
    int listen_fd = -1;
    int wake_pipe[2] = {-1, -1};
#endif

    struct Entry {
        std::string id;
        std::string module;
        Patch patch;
    };
    mutable std::mutex mu;      // guards entries / next_id
    std::deque<Entry> entries;  // deque: references stay valid on push_back
    unsigned next_id = 1;
};

Agent::Agent() : impl_(std::make_unique<Impl>()) {}

Agent::~Agent() { stop(); }

namespace {

// A loaded patch module and its entry point.
struct LoadedModule {
    PatchEntryFn entry = nullptr;
};

#if defined(_WIN32)

std::wstring widen(const std::string& s) {
    const int n = ::MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, nullptr, 0);
    if (n <= 1) return {};
    std::wstring w(static_cast<std::size_t>(n - 1), L'\0');
    ::MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, &w[0], n);
    return w;
}

std::string last_error_text(DWORD e = ::GetLastError()) { return "Windows error " + std::to_string(e); }

// SID of the current user as an SDDL string ("S-1-5-21-...").
bool current_user_sid(std::string& out, std::vector<std::uint8_t>* raw = nullptr) {
    HANDLE token = nullptr;
    if (!::OpenProcessToken(::GetCurrentProcess(), TOKEN_QUERY, &token)) return false;
    DWORD len = 0;
    ::GetTokenInformation(token, TokenUser, nullptr, 0, &len);
    std::vector<std::uint8_t> buf(len);
    const bool ok = len != 0 && ::GetTokenInformation(token, TokenUser, buf.data(), len, &len);
    ::CloseHandle(token);
    if (!ok) return false;
    PSID sid = reinterpret_cast<TOKEN_USER*>(buf.data())->User.Sid;
    char* str = nullptr;
    if (!::ConvertSidToStringSidA(sid, &str)) return false;
    out = str;
    ::LocalFree(str);
    if (raw) {
        raw->assign(static_cast<std::uint8_t*>(sid), static_cast<std::uint8_t*>(sid) + ::GetLengthSid(sid));
    }
    return true;
}

bool overlapped_wait(HANDLE h, OVERLAPPED& ov, HANDLE stop, DWORD timeout_ms, DWORD& transferred) {
    HANDLE events[2] = {ov.hEvent, stop};
    const DWORD w = ::WaitForMultipleObjects(stop ? 2 : 1, events, FALSE, timeout_ms);
    if (w != WAIT_OBJECT_0) {
        ::CancelIoEx(h, &ov);
        ::GetOverlappedResult(h, &ov, &transferred, TRUE);
        return false;
    }
    return ::GetOverlappedResult(h, &ov, &transferred, FALSE) != 0;
}

bool pipe_read_line(HANDLE h, HANDLE stop, std::string& line) {
    line.clear();
    OVERLAPPED ov;
    ZeroMemory(&ov, sizeof ov);
    ov.hEvent = ::CreateEventW(nullptr, TRUE, FALSE, nullptr);
    bool ok = false;
    while (line.size() < 4096) {
        char buf[256];
        DWORD got = 0;
        ::ResetEvent(ov.hEvent);
        if (!::ReadFile(h, buf, sizeof buf, nullptr, &ov) && ::GetLastError() != ERROR_IO_PENDING) break;
        if (!overlapped_wait(h, ov, stop, 5000, got) || got == 0) break;
        for (DWORD i = 0; i < got; ++i) {
            if (buf[i] == '\n') {
                ok = true;
                break;
            }
            if (buf[i] != '\r') line.push_back(buf[i]);
        }
        if (ok) break;
    }
    ::CloseHandle(ov.hEvent);
    return ok;
}

void pipe_write_all(HANDLE h, HANDLE stop, const std::string& s) {
    OVERLAPPED ov;
    ZeroMemory(&ov, sizeof ov);
    ov.hEvent = ::CreateEventW(nullptr, TRUE, FALSE, nullptr);
    std::size_t done = 0;
    while (done < s.size()) {
        DWORD put = 0;
        ::ResetEvent(ov.hEvent);
        if (!::WriteFile(h, s.data() + done, static_cast<DWORD>(s.size() - done), nullptr, &ov) &&
            ::GetLastError() != ERROR_IO_PENDING)
            break;
        if (!overlapped_wait(h, ov, stop, 5000, put) || put == 0) break;
        done += put;
    }
    ::CloseHandle(ov.hEvent);
}

Result open_and_load(const std::string& path, bool check_owner, LoadedModule& out) {
    const std::wstring wpath = widen(path);
    // No write sharing: nobody can modify the file between the check and the load.
    HANDLE f = ::CreateFileW(wpath.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING,
                             FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
    if (f == INVALID_HANDLE_VALUE) return {Status::NotFound, "cannot open " + path + ": " + last_error_text()};
    BY_HANDLE_FILE_INFORMATION info;
    if (!::GetFileInformationByHandle(f, &info) || (info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) ||
        (info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT)) {
        ::CloseHandle(f);
        return {Status::InvalidArgument, path + " is not a regular file"};
    }
    if (check_owner) {
        PSID owner = nullptr;
        PSECURITY_DESCRIPTOR sd = nullptr;
        if (::GetSecurityInfo(f, SE_FILE_OBJECT, OWNER_SECURITY_INFORMATION, &owner, nullptr, nullptr, nullptr, &sd) !=
            ERROR_SUCCESS) {
            ::CloseHandle(f);
            return {Status::PermissionDenied, "cannot read the owner of " + path};
        }
        std::string me;
        std::vector<std::uint8_t> my_sid;
        bool allowed = current_user_sid(me, &my_sid) && ::EqualSid(owner, my_sid.data());
        allowed = allowed || ::IsWellKnownSid(owner, WinBuiltinAdministratorsSid) ||
                  ::IsWellKnownSid(owner, WinLocalSystemSid);
        char* owner_str = nullptr;
        if (!allowed && ::ConvertSidToStringSidA(owner, &owner_str)) {  // NT SERVICE\TrustedInstaller
            allowed = std::strncmp(owner_str, "S-1-5-80-956008885-", 19) == 0;
            ::LocalFree(owner_str);
        }
        ::LocalFree(sd);
        if (!allowed) {
            ::CloseHandle(f);
            return {Status::PermissionDenied, path + " is owned by another user"};
        }
    }
    // Not a PE image: refuse before the loader sees it.
    char mz[2] = {};
    DWORD got = 0;
    if (!::ReadFile(f, mz, sizeof mz, &got, nullptr) || got != sizeof mz || mz[0] != 'M' || mz[1] != 'Z') {
        ::CloseHandle(f);
        return {Status::InvalidArgument, path + " is not a PE module"};
    }
    // No "bad image" or "file not found" dialog boxes from the loader.
    DWORD old_mode = 0;
    ::SetThreadErrorMode(SEM_FAILCRITICALERRORS | SEM_NOOPENFILEERRORBOX, &old_mode);
    HMODULE h = ::LoadLibraryW(wpath.c_str());
    const DWORD err = ::GetLastError();
    ::SetThreadErrorMode(old_mode, nullptr);
    ::CloseHandle(f);
    if (!h) return {Status::InvalidArgument, "LoadLibrary failed: " + last_error_text(err)};
    out.entry = reinterpret_cast<PatchEntryFn>(reinterpret_cast<void*>(::GetProcAddress(h, "vajra_patch_entry")));
    if (!out.entry) return {Status::NotFound, path + " does not export vajra_patch_entry"};
    return Result::ok();
}

#else  // POSIX

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

Result open_and_load(const std::string& path, bool check_owner, LoadedModule& out) {
    const int fd = ::open(path.c_str(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) return {Status::NotFound, "cannot open " + path + ": " + std::strerror(errno)};
    struct stat st;
    if (::fstat(fd, &st) != 0 || !S_ISREG(st.st_mode)) {
        ::close(fd);
        return {Status::InvalidArgument, path + " is not a regular file"};
    }
    if (check_owner) {
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
    out.entry = reinterpret_cast<PatchEntryFn>(::dlsym(handle, "vajra_patch_entry"));
    if (!out.entry) return {Status::NotFound, path + " does not export vajra_patch_entry"};
    return Result::ok();
}

#endif

}  // namespace

#if defined(_WIN32)

Result Agent::start(const Options& options) {
    if (impl_->running) return {Status::AlreadyApplied, "agent is already running"};
    if (options.socket_path.rfind("\\\\.\\pipe\\", 0) != 0)
        return {Status::InvalidArgument, "on Windows the agent address must be a pipe name like \\\\.\\pipe\\name"};
    std::string sid;
    if (!current_user_sid(sid)) return {Status::Internal, "cannot determine the current user"};
    // Protected DACL: full access for the current user only.
    const std::string sddl = "D:P(A;;GA;;;" + sid + ")";
    PSECURITY_DESCRIPTOR sd = nullptr;
    if (!::ConvertStringSecurityDescriptorToSecurityDescriptorA(sddl.c_str(), SDDL_REVISION_1, &sd, nullptr))
        return {Status::Internal, "cannot build the pipe security descriptor"};
    SECURITY_ATTRIBUTES sa;
    sa.nLength = sizeof sa;
    sa.lpSecurityDescriptor = sd;
    sa.bInheritHandle = FALSE;
    HANDLE pipe = ::CreateNamedPipeW(widen(options.socket_path).c_str(),
                                     PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE | FILE_FLAG_OVERLAPPED,
                                     PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS, 1,
                                     4096, 4096, 0, &sa);
    const DWORD err = ::GetLastError();
    ::LocalFree(sd);
    if (pipe == INVALID_HANDLE_VALUE)
        return {err == ERROR_ACCESS_DENIED ? Status::PermissionDenied : Status::IoError,
                "cannot create pipe " + options.socket_path + " (in use?): " + last_error_text(err)};
    impl_->stop_event = ::CreateEventW(nullptr, TRUE, FALSE, nullptr);
    impl_->pipe = pipe;
    impl_->opts = options;
    impl_->running = true;
    impl_->thread = std::thread([this] {
        HANDLE h = impl_->pipe;
        HANDLE stop = impl_->stop_event;
        OVERLAPPED ov;
        ZeroMemory(&ov, sizeof ov);
        ov.hEvent = ::CreateEventW(nullptr, TRUE, FALSE, nullptr);
        for (;;) {
            ::ResetEvent(ov.hEvent);
            bool connected = ::ConnectNamedPipe(h, &ov) != 0;
            if (!connected) {
                const DWORD e = ::GetLastError();
                if (e == ERROR_PIPE_CONNECTED) {
                    connected = true;
                } else if (e == ERROR_IO_PENDING) {
                    DWORD dummy = 0;
                    connected = overlapped_wait(h, ov, stop, INFINITE, dummy);
                }
            }
            if (::WaitForSingleObject(stop, 0) == WAIT_OBJECT_0) break;
            if (connected) {
                std::string line;
                if (pipe_read_line(h, stop, line)) pipe_write_all(h, stop, handle_command(line));
                ::FlushFileBuffers(h);
            }
            ::DisconnectNamedPipe(h);
        }
        ::CloseHandle(ov.hEvent);
    });
    return Result::ok();
}

void Agent::stop() {
    if (!impl_->running) return;
    ::SetEvent(impl_->stop_event);
    impl_->thread.join();
    ::CloseHandle(impl_->pipe);
    ::CloseHandle(impl_->stop_event);
    impl_->pipe = INVALID_HANDLE_VALUE;
    impl_->stop_event = nullptr;
    impl_->running = false;
}

#else  // POSIX

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

#endif

Result Agent::apply_module(const std::string& path, std::string* id, std::string* message) {
    LoadedModule mod;
    if (Result r = open_and_load(path, impl_->opts.check_module_owner, mod); !r) return r;

    Transaction tx(impl_->opts.patch);
    PatchContext ctx;
    ctx.heap = impl_->opts.heap;
    ctx.user = impl_->opts.user;
    ctx.tx = &tx;
    const int rc = mod.entry(&ctx);
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
