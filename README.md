# coresight-decoder

coresight-decoder is an experimental CoreSight decoder dedicated to fuzzing purposes. It currently supports CoreSight trace from ARM64 ETMv4 or later. We tested it with ARM64 Ubuntu 20.04 and 18.04.

NOTE: coresight-decoder is in the early development stage. Not applicable for production use.

## Installation

coresight-decoder depends on [Capstone](https://github.com/aquynh/capstone) version 4.0 or later. This restriction is due to a bug in the ARM64 branch disassembly [#1213](https://github.com/aquynh/capstone/pull/1213). **Please do not use older versions (e.g. `libcapstone-dev` from Ubuntu apt packages).**

In the below example, install Capstone from the source.

```bash
git clone https://github.com/aquynh/capstone.git
cd capstone
git checkout 4.0.2 # checkout the latest version
sudo ./make.sh install
```

Next, checkout and build coresight-decoder.

```bash
git clone https://github.com/RICSecLab/coresight-decoder.git
cd coresight-decoder
make
```

After the build is finished, the static library `libcsdec.a` and the simple decoder application `processor` should be in the root directory.
The Makefile also provides `make test` for testing and `make debug` for a debug build.

Refer to [HOWTO](HOWTO.md) for the library usage example.

### Notes on using coresight-decoder

To use `libcsdec.a`, link it with the `-lcapstone` flag to the Capstone shared library. The `processor` application will show usage when no argument is supplied.

## Contributing

Please open GitHub Issues and Pull Requests. All commits must include a `Signed-off-by` line using `git commit --signoff` to enforce the [Developer Certificate of Origin (DCO)](https://developercertificate.org).

## License

coresight-decoder is released under the [Apache License, Version 2.0](https://opensource.org/licenses/Apache-2.0).

## Acknowledgements

This project has received funding from the Acquisition, Technology & Logistics Agency (ATLA) under the Innovative Science and Technology Initiative for Security 2020 (JPJ004596).
