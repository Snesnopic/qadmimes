#include <qadmimes.hpp>
#include <fstream>
#include <array>
#include <algorithm>
#include <string_view>
#include <cstring>
#include <cctype>
#include <span>

namespace qadmimes {

    static constexpr size_t MIN_ZIP_HEADER_SIZE = 30;
    static constexpr size_t READ_BUFFER_SIZE = 65536; // 64KB for ISO-9660 support
    static constexpr size_t MIN_RIFF_SIZE = 12;
    static constexpr size_t RIFF_TYPE_OFFSET = 8;

    // References to the static tables defined in magic_database.cpp
    extern const std::span<const MagicRule> global_magic_rules_span;
    extern const std::span<const ExtensionRule> global_extension_rules_span;

    std::string_view MimeDetector::sniff_container(std::span<const uint8_t> buffer) {
        if (buffer.size() < MIN_ZIP_HEADER_SIZE) {
            return "application/zip";
        }

        const std::string_view view(reinterpret_cast<const char*>(buffer.data()), buffer.size());

        // OOXML (Office Open XML) detection
        if (view.find("word/") != std::string_view::npos) {
            return "application/vnd.openxmlformats-officedocument.wordprocessingml.document";
        }
        if (view.find("xl/") != std::string_view::npos) {
            return "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet";
        }
        if (view.find("ppt/") != std::string_view::npos) {
            return "application/vnd.openxmlformats-officedocument.presentationml.presentation";
        }
        
        // ODF (Open Document Format) and EPUB
        if (view.find("mimetypeapplication/vnd.oasis.opendocument.text") != std::string_view::npos) {
            return "application/vnd.oasis.opendocument.text";
        }
        if (view.find("mimetypeapplication/vnd.oasis.opendocument.spreadsheet") != std::string_view::npos) {
            return "application/vnd.oasis.opendocument.spreadsheet";
        }
        if (view.find("mimetypeapplication/vnd.oasis.opendocument.presentation") != std::string_view::npos) {
            return "application/vnd.oasis.opendocument.presentation";
        }
        if (view.find("mimetypeapplication/epub+zip") != std::string_view::npos) {
            return "application/epub+zip";
        }

        // Android and Java packages
        if (view.find("AndroidManifest.xml") != std::string_view::npos) {
            return "application/vnd.android.package-archive";
        }
        if (view.find("META-INF/MANIFEST.MF") != std::string_view::npos) {
            return "application/java-archive";
        }

        // Specialized ZIP-based formats
        if (view.find("mimetypeimage/openraster") != std::string_view::npos) {
            return "image/openraster";
        }
        if (view.find(".dwfx") != std::string_view::npos) {
            return "model/vnd.dwfx+xps";
        }
        if (view.find(".3mf") != std::string_view::npos) {
            return "application/vnd.ms-package.3dmanufacturing-3dmodel+xml";
        }
        if (view.find(".kml") != std::string_view::npos) {
            return "application/vnd.google-earth.kmz";
        }

        return "application/zip";
    }

    std::string_view MimeDetector::detect(std::span<const uint8_t> buffer) {
        if (buffer.empty()) {
            return "application/octet-stream";
        }

        for (const auto& rule : global_magic_rules_span) {
            if (buffer.size() < rule.offset + rule.pattern.size()) {
                continue;
            }

            bool match = true;
            if (rule.mask.empty()) {
                if (std::memcmp(buffer.data() + rule.offset, rule.pattern.data(), rule.pattern.size()) != 0) {
                    match = false;
                }
            } else {
                // Apply bitmask for fuzzy matches (e.g., MP3 frames)
                for (size_t i = 0; i < rule.pattern.size(); ++i) {
                    const auto buf_byte = static_cast<uint8_t>(buffer[rule.offset + i]);
                    const auto msk_byte = static_cast<uint8_t>(rule.mask[i]);
                    const auto pat_byte = static_cast<uint8_t>(rule.pattern[i]);
                    if ((buf_byte & msk_byte) != (pat_byte & msk_byte)) {
                        match = false;
                        break;
                    }
                }
            }

            if (match) {
                // Handle complex container formats that require deeper sniffing
                if (rule.mime == "application/zip") {
                    return sniff_container(buffer);
                }
                if (rule.mime == "application/x-ole-storage") {
                    const std::string_view view(reinterpret_cast<const char*>(buffer.data()), buffer.size());
                    if (view.find("WordDocument") != std::string_view::npos) { return "application/msword"; }
                    if (view.find("Workbook") != std::string_view::npos || view.find("Book") != std::string_view::npos) {
                        return "application/vnd.ms-excel";
                    }
                    if (view.find("PowerPoint") != std::string_view::npos) { return "application/vnd.ms-powerpoint"; }
                    if (view.find("MSI ") != std::string_view::npos) { return "application/x-msi"; }
                    if (view.find("MSProject") != std::string_view::npos) { return "application/vnd.ms-project"; }
                    return "application/x-ole-storage";
                }
                if (rule.mime == "application/x-riff") {
                    if (buffer.size() < MIN_RIFF_SIZE) {
                        return "application/x-riff";
                    }
                    if (std::memcmp(buffer.data() + RIFF_TYPE_OFFSET, "WEBP", 4) == 0) { return "image/webp"; }
                    if (std::memcmp(buffer.data() + RIFF_TYPE_OFFSET, "WAVE", 4) == 0) { return "audio/wav"; }
                    if (std::memcmp(buffer.data() + RIFF_TYPE_OFFSET, "AVI ", 4) == 0) { return "video/x-msvideo"; }
                    return "application/x-riff";
                }
                if (rule.mime == "video/x-matroska") {
                    const std::string_view view(reinterpret_cast<const char*>(buffer.data()), buffer.size());
                    if (view.find("webm") != std::string_view::npos) { return "video/webm"; }
                    return "video/x-matroska";
                }
                if (rule.mime == "application/xml") {
                    const std::string_view view(reinterpret_cast<const char*>(buffer.data()), buffer.size());
                    if (view.find("<svg") != std::string_view::npos) { return "image/svg+xml"; }
                    return "application/xml";
                }
                return rule.mime;
            }
        }

        return "application/octet-stream";
    }

    std::string_view MimeDetector::detect(const std::filesystem::path& path) {
        std::ifstream file(path, std::ios::binary);
        if (!file) {
            return "application/octet-stream";
        }

        std::array<uint8_t, READ_BUFFER_SIZE> buffer{}; 
        file.read(reinterpret_cast<char*>(buffer.data()), buffer.size());
        const auto bytes_read = static_cast<size_t>(file.gcount());

        std::string_view mime = detect(std::span(buffer.data(), bytes_read));

        // Fallback to extension database if binary sniffing was inconclusive
        if (mime == "application/octet-stream" || mime == "application/zip" || mime == "application/x-ole-storage" || mime == "application/x-riff") {
            std::string ext = path.extension().string();
            std::ranges::transform(ext, ext.begin(), [](unsigned char char_code) -> char {
                return static_cast<char>(std::tolower(char_code));
            });

            for (const auto& rule : global_extension_rules_span) {
                if (ext == rule.extension) {
                    return rule.mime;
                }
            }
        }

        return mime;
    }

} // namespace qadmimes
