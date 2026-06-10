#include <iostream>
#include <filesystem>
#include <vector>
#include <string>
#include <qadmimes.hpp>

namespace fs = std::filesystem;

static void process_single_path(const fs::path& file_path, const bool brief, const bool force_filename) {
    if (!fs::exists(file_path)) {
        std::cerr << "cannot open '" << file_path.string() << "' (No such file or directory)" << std::endl;
        return;
    }

    if (fs::is_directory(file_path)) {
        for (const auto& entry : fs::recursive_directory_iterator(file_path)) {
            if (entry.is_regular_file()) {
                process_single_path(entry.path(), brief, true);
            }
        }
        return;
    }

    try {
        const std::string_view mime_type = qadmimes::MimeDetector::detect(file_path);
        if (brief && !force_filename) {
            std::cout << mime_type << std::endl;
        } else {
            std::cout << file_path.string() << ": " << mime_type << std::endl;
        }
    } catch (const std::exception& e) {
        std::cerr << "Error processing " << file_path << ": " << e.what() << std::endl;
    }
}

int main(int argc, char** argv) {
    if (argc < 2) {
        std::cout << "Usage: qadmimes-cli [-b] <file_or_dir>..." << std::endl;
        return EXIT_FAILURE;
    }

    bool brief = false;
    std::vector<std::string> paths;

    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "-b" || arg == "--brief") {
            brief = true;
        } else {
            paths.push_back(arg);
        }
    }

    if (paths.empty()) {
        std::cout << "Usage: qadmimes-cli [-b] <file_or_dir>..." << std::endl;
        return EXIT_FAILURE;
    }

    for (const auto& p : paths) {
        process_single_path(p, brief, false);
    }

    return EXIT_SUCCESS;
}
