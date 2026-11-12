// Agent: socket protocol through vajractl, module checks, apply and revert.
// SPDX-License-Identifier: MIT
#include <sys/stat.h>
#include <unistd.h>

#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <string>

#include "check.hpp"
#include "vajra/vajra.hpp"

using namespace vajra;

extern "C" VAJRA_PATCHABLE int agent_target(int x) {
    int r = x + 1;
    __asm__ volatile("" : "+r"(r));
    return r;
}

namespace {

struct CounterV1 {
    std::int32_t value;
};
const TypeDesc kCounterV1 = describe<CounterV1>("Counter", 1, {VAJRA_FIELD(CounterV1, value)});

template <class F>
F* opaque(F* f) {
    F* volatile p = f;
    return p;
}

std::string run(const std::string& cmd, int* status = nullptr) {
    std::string out;
    FILE* p = ::popen(cmd.c_str(), "r");
    if (!p) return out;
    char buf[512];
    while (std::fgets(buf, sizeof buf, p)) out += buf;
    const int st = ::pclose(p);
    if (status) *status = WIFEXITED(st) ? WEXITSTATUS(st) : -1;
    return out;
}

void copy_file(const std::string& from, const std::string& to) {
    std::ifstream in(from, std::ios::binary);
    std::ofstream out(to, std::ios::binary);
    out << in.rdbuf();
}

}  // namespace

TEST(agent_end_to_end) {
    char dir_template[] = "/tmp/vajra-agent-XXXXXX";
    char* dir = ::mkdtemp(dir_template);
    CHECK(dir != nullptr);
    if (!dir) return;
    const std::string sock = std::string(dir) + "/agent.sock";

    Heap heap;
    CHECK_OK(heap.register_type(kCounterV1));
    void* counter = heap.allocate("Counter", 1);
    static_cast<CounterV1*>(counter)->value = 41;
    heap.add_root(&counter);

    Agent agent;
    Agent::Options o;
    o.socket_path = sock;
    o.heap = &heap;
    CHECK_OK(agent.start(o));

    struct stat st;
    CHECK(::stat(sock.c_str(), &st) == 0 && (st.st_mode & 0777) == 0600);

    int status = -1;
    std::string out = run(std::string(VAJRACTL) + " " + sock + " ping", &status);
    CHECK_EQ(status, 0);
    CHECK(out.find("ok vajra") == 0);

    CHECK_EQ(opaque(&agent_target)(2), 3);
    out = run(std::string(VAJRACTL) + " " + sock + " apply " + VAJRA_TEST_PATCH, &status);
    CHECK_EQ(status, 0);
    CHECK(out.find("ok p1 counter-v2") == 0);
    CHECK_EQ(opaque(&agent_target)(2), 2000);
    CHECK_EQ(heap.version("Counter"), 2u);
    CHECK_EQ(static_cast<std::int64_t*>(counter)[0], 41);
    CHECK_EQ(static_cast<std::int64_t*>(counter)[1], 2);

    out = run(std::string(VAJRACTL) + " " + sock + " list", &status);
    CHECK(out.find("p1 active") != std::string::npos);

    out = run(std::string(VAJRACTL) + " " + sock + " revert p1", &status);
    CHECK_EQ(status, 0);
    CHECK_EQ(opaque(&agent_target)(2), 3);
    CHECK_EQ(heap.version("Counter"), 1u);
    CHECK_EQ(static_cast<CounterV1*>(counter)->value, 41);
    out = run(std::string(VAJRACTL) + " " + sock + " revert p1", &status);
    CHECK_EQ(status, 1);
    CHECK(out.find("not applied") != std::string::npos);

    // Module checks: missing file, group-writable module, unknown command.
    out = run(std::string(VAJRACTL) + " " + sock + " apply /nonexistent/x.so", &status);
    CHECK_EQ(status, 2);  // vajractl cannot resolve the path
    const std::string writable = std::string(dir) + "/writable.so";
    copy_file(VAJRA_TEST_PATCH, writable);
    ::chmod(writable.c_str(), 0664);
    std::string id, msg;
    CHECK_STATUS(agent.apply_module(writable, &id, &msg), Status::PermissionDenied);
    ::chmod(writable.c_str(), 0644);
    const std::string not_elf = std::string(dir) + "/not_elf.so";
    { std::ofstream(not_elf) << "hello"; }
    CHECK_STATUS(agent.apply_module(not_elf, &id, &msg), Status::InvalidArgument);
    CHECK(agent.handle_command("bogus").find("error unknown command") == 0);

    // The same module applied again through the API (a second copy of the file).
    CHECK_OK(agent.apply_module(writable, &id, &msg));
    CHECK(id == "p2");
    CHECK_EQ(opaque(&agent_target)(3), 3000);
    CHECK_OK(agent.revert("p2"));
    CHECK_EQ(opaque(&agent_target)(3), 4);

    agent.stop();
    CHECK(::access(sock.c_str(), F_OK) != 0);  // socket removed
    ::unlink(writable.c_str());
    ::unlink(not_elf.c_str());
    ::rmdir(dir);
}

TEST_MAIN()
