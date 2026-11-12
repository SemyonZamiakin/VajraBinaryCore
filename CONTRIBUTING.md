# Contributing to Vajra Binary Core

Thanks for your interest. Bug reports (especially instruction encodings the decoder gets wrong or refuses, and prologues the relocator should handle), results from other Linux distributions and Windows versions, and focused pull requests are welcome.

## Before you start

- For anything larger than a small fix, open an issue first so the approach can be agreed.
- Keep changes focused: one topic per pull request.

## Build and test

Linux:

```bash
scripts/check.sh            # gcc, clang, debug, asan (+ubsan), tsan
scripts/check.sh gcc asan   # a subset
```

Windows (MSYS2 MINGW64 shell, or Git Bash with `C:\msys64\mingw64\bin` on `PATH`):

```bash
scripts/check-windows.sh
```

Both build with `-Werror` and run every test, including the objdump cross-check of the decoder (needs `objdump`) and the live-patching demo (needs `bash`).

## Rules for the code

- Anything that runs between `world_stop()` and `world_resume()` must not allocate, take locks other threads may hold, or call library functions that might. Build error messages after the resume. See section 2 of [docs/DESIGN.md](docs/DESIGN.md).
- The decoder and relocator refuse what they do not fully understand. A new encoding needs a test in `test_decoder` and must survive `decoder_vs_objdump`; a new relocation rule needs a byte-exact test in `test_relocate` and an executing test in `test_hook`.
- A transaction is all-or-nothing. New operations need fault-injection coverage in `test_transaction` (`sys::set_write_fault_countdown`).
- Platform code lives in `sys_linux.cpp` / `sys_windows.cpp` and `stop_linux.cpp` / `stop_windows.cpp`; everything else stays portable.
- C++17, no external dependencies, warning-free with GCC and Clang (`-Wall -Wextra -Wpedantic -Wshadow`).

## Commit messages

Short imperative subject line, a blank line, then what changed and why.

## License

By contributing you agree that your contribution is licensed under the MIT License of this repository.
