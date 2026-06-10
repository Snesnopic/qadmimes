# qadmimes

Lightweight alternative to `libmagic` for MIME detection.

## Build

```bash
mkdir build && cd build
cmake -DCMAKE_BUILD_TYPE=Release ..
make
```

## Usage

### CLI
```bash
qadmimes <file_or_dir>
qadmimes --brief <file_or_dir> # Only output MIME types
```

### Library
```cpp
#include <qadmimes.hpp>

// detect from file path
std::string_view mime = qadmimes::MimeDetector::detect("example.png");

// detect from memory buffer
std::vector<uint8_t> buffer = read_file_start("example.docx");
std::string_view mime = qadmimes::MimeDetector::detect(buffer);
```
