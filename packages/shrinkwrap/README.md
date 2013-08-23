## Scripts for making "shrink-wrap" httest binaries

by $(whois jexler.net)

[![jexler logo](http://www.gravatar.com/avatar/9022d38f949fccf36a94e0f444327f6b.jpg)](http://www.jexler.net/)

### Resulting Binaries

- idea: distributable binaries that work "out of the box"
- mac/unix: apr, openssl, etc. are linked statically
- win: DLLs for these libs are included
- built including lua, libxml2 and js

### Build Script

- mac/unix:
  - lib sources are downloaded
  - libs are built from source
  - htt is built with these libs linked statically
  - some basic tests are run
  - tests are run (make check in test dir)
- win:
  - built libs and DLLs and header files are downloaded
  - htt is configured with dummy lib config files
  - a visual c++ solution is generated
  - htt is built with visual c++
  - some basic tests are run
  - tests are run (equiv. make check in test dir)

### Prerequisites

- mac/unix:
  - usual developer tools installed*
  - if not mac or linux, you may need to modify scripts
- win:
  - cygwin with usual developer tools installed*
  - visual c++ express 2010

\* If the build fails, just add what is missing ;)

### Usage

- make.sh (clean|all|sln)*
- default target is all
- clean: cleans target dir
- all:   builds binaries on same platform
- sln:   creates a visual c++ solution (on win and unix)

### Output

- build: target/build.log
- test report: target/report-<ver>-<os>.html
- binaries: target/httest-<ver>-<os>[.tar.gz|.zip]

### Download

Recent httest versions and nightly builds for mac, win, linux 32 and 64 bit:

- [http://www.jexler.net/htt](http://www.jexler.net/htt)

