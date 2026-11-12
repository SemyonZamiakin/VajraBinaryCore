// Agent: protocol through vajractl (Unix socket / named pipe), module checks,
// apply and revert.
// SPDX-License-Identifier: MIT
#include <sys/stat.h>

#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <string>

#if !defined(_WIN32)
#include <unistd.h>
#else
#include <direct.h>
#include <process.h>
#endif

#include "check.hpp"
#include "platform.hpp"
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

void copy_file(const std::string& from, const std::string& to) {
    std::ifstream in(from, std::ios::binary);
    std::ofstream out(to, std::ios::binary);
    out << in.rdbuf();
}

// A private scratch directory and the agent address.
struct Scratch {
    std::string dir;
    std::string address;
    Scratch() {
#if defined(_WIN32)
        char tmp[MAX_PATH];
        ::GetTempPathA(sizeof tmp, tmp);
        dir = std::string(tmp) + "vajra-agent-" + std::to_string(::_getpid());
        ::_mkdir(dir.c_str());
        address = "\\\\.\\pipe\\vajra-agent-test-" + std::to_string(::_getpid());
#else
        char tmpl[] = "/tmp/vajra-agent-XXXXXX";
        if (char* d = ::mkdtemp(tmpl)) dir = d;
        address = dir + "/agent.sock";
#endif
    }
    ~Scratch() {
#if defined(_WIN32)
        ::_rmdir(dir.c_str());
#else
        ::rmdir(dir.c_str());
#endif
    }
};

}  // namespace

TEST(agent_end_to_end) {
    Scratch s;
    CHECK(!s.dir.empty());
    if (s.dir.empty()) return;
    const std::string ctl = testplat::quote(VAJRACTL) + " " + testplat::quote(s.address);

    Heap heap;
    CHECK_OK(heap.register_type(kCounterV1));
    void* counter = heap.allocate("Counter", 1);
    static_cast<CounterV1*>(counter)->value = 41;
    heap.add_root(&counter);

    Agent agent;
    Agent::Options o;
    o.socket_path = s.address;
    o.heap = &heap;
    CHECK_OK(agent.start(o));
#if !defined(_WIN32)
    struct stat st;
    CHECK(::stat(s.address.c_str(), &st) == 0 && (st.st_mode & 0777) == 0600);
#else
    // A second agent cannot take over the same pipe name.
    Agent squatter;
    CHECK(!squatter.start(o).is_ok());
#endif

    int status = -1;
    std::string out = testplat::run(ctl + " ping", &status);
    CHECK_EQ(status, 0);
    CHECK(out.find("ok vajra") == 0);

    CHECK_EQ(opaque(&agent_target)(2), 3);
    out = testplat::run(ctl + " apply " + testplat::quote(VAJRA_TEST_PATCH), &status);
    CHECK_EQ(status, 0);
    CHECK(out.find("ok p1 counter-v2") == 0);
    CHECK_EQ(opaque(&agent_target)(2), 2000);
    CHECK_EQ(heap.version("Counter"), 2u);
    CHECK_EQ(static_cast<std::int64_t*>(counter)[0], 41);
    CHECK_EQ(static_cast<std::int64_t*>(counter)[1], 2);

    out = testplat::run(ctl + " list", &status);
    CHECK(out.find("p1 active") != std::string::npos);

    out = testplat::run(ctl + " revert p1", &status);
    CHECK_EQ(status, 0);
    CHECK_EQ(opaque(&agent_target)(2), 3);
    CHECK_EQ(heap.version("Counter"), 1u);
    CHECK_EQ(static_cast<CounterV1*>(counter)->value, 41);
    out = testplat::run(ctl + " revert p1", &status);
    CHECK_EQ(status, 1);
    CHECK(out.find("not applied") != std::string::npos);

    // Module checks: missing file, unsafe permissions (Linux), not a module, unknown command.
    out = testplat::run(ctl + " apply " + testplat::quote(s.dir + "/nonexistent.so"), &status);
    CHECK_EQ(status, 2);  // vajractl cannot resolve the path
#if defined(_WIN32)
    const std::string copy = s.dir + "\\copy.dll";
#else
    const std::string copy = s.dir + "/copy.so";
#endif
    copy_file(VAJRA_TEST_PATCH, copy);
    std::string id, msg;
#if !defined(_WIN32)
    ::chmod(copy.c_str(), 0664);
    CHECK_STATUS(agent.apply_module(copy, &id, &msg), Status::PermissionDenied);
    ::chmod(copy.c_str(), 0644);
#endif
    const std::string not_module = s.dir + "/not_a_module.bin";
    { std::ofstream(not_module) << "hello"; }
    CHECK_STATUS(agent.apply_module(not_module, &id, &msg), Status::InvalidArgument);
    CHECK(agent.handle_command("bogus").find("error unknown command") == 0);

    // A second copy of the module applied through the API.
    CHECK_OK(agent.apply_module(copy, &id, &msg));
    CHECK(id == "p2");
    CHECK_EQ(opaque(&agent_target)(3), 3000);
    CHECK_OK(agent.revert("p2"));
    CHECK_EQ(opaque(&agent_target)(3), 4);

    agent.stop();
#if !defined(_WIN32)
    CHECK(::access(s.address.c_str(), F_OK) != 0);  // socket removed
#endif
    std::remove(not_module.c_str());
#if !defined(_WIN32)
    std::remove(copy.c_str());  // on Windows the DLL stays loaded (modules are never unloaded)
#endif
}

TEST_MAIN()
