# samples/

Reference implementations from the original research blog posts that inspired
this project. These are **archival / educational only** — production code lives
in `src/cascade.cpp`.

- `byovd_sample2.cpp` — minimal PPL strip via BiosToolCommonDriver.sys.
  Demonstrates the core primitive without the full callback/dump/exfil chain.
- `dump_the_goodz_7.cpp` — MiniDumpWriteDump + XOR obfuscation reference.
  Not used at runtime; cascade uses `--dump-rpm` instead (avoids MiniDump API).

Do not build these into your operational payload; they are documented for
provenance and to make it easy to compare the current implementation to the
original public techniques.
