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

    static std::string_view sniff_isobmff(const std::span<const uint8_t> buffer) {
        if (buffer.size() < 12) return "video/mp4";
        const char* brand = reinterpret_cast<const char*>(buffer.data() + 8);

        if (std::memcmp(brand, "3g2", 3) == 0) return "video/3gpp2";
        if (std::memcmp(brand, "3gp", 3) == 0) return "video/3gpp";
        if (std::memcmp(brand, "M4A ", 4) == 0) return "audio/x-m4a";
        if (std::memcmp(brand, "M4B ", 4) == 0) return "audio/mp4";
        if (std::memcmp(brand, "M4V ", 4) == 0) return "video/x-m4v";
        if (std::memcmp(brand, "qt  ", 4) == 0) return "video/quicktime";
        if (std::memcmp(brand, "mqt ", 4) == 0) return "video/quicktime";
        if (std::memcmp(brand, "heic", 4) == 0) return "image/heic";
        if (std::memcmp(brand, "heis", 4) == 0) return "image/heic";
        if (std::memcmp(brand, "heim", 4) == 0) return "image/heic";
        if (std::memcmp(brand, "heix", 4) == 0) return "image/heic";
        if (std::memcmp(brand, "hevc", 4) == 0) return "image/heic-sequence";
        if (std::memcmp(brand, "hevx", 4) == 0) return "image/heic-sequence";
        if (std::memcmp(brand, "mif1", 4) == 0) return "image/heif";
        if (std::memcmp(brand, "avif", 4) == 0) return "image/avif";
        if (std::memcmp(brand, "avis", 4) == 0) return "image/avif";
        if (std::memcmp(brand, "f4v ", 4) == 0) return "video/x-f4v";
        return "video/mp4";
    }

    std::string_view MimeDetector::sniff_container(const std::span<const uint8_t> buffer) {
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

    std::string_view MimeDetector::detect(const std::span<const uint8_t> buffer) {
        if (buffer.empty()) {
            return std::string_view{};
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
                if (rule.mime == "video/iso.base-media") {
                    return sniff_isobmff(buffer);
                }
                if (rule.mime == "application/x-ole-storage") {
                    const std::string_view view(reinterpret_cast<const char*>(buffer.data()), buffer.size());
                    // OLE directory stores stream names as UTF-16LE. Use char arrays to avoid
                    // hex escape greediness (\x00d would be chr(13) instead of chr(0)+'d').
                    static constexpr char WORD_W_B[]   = {'W',0,'o',0,'r',0,'d',0,'D',0,'o',0,'c',0,'u',0,'m',0,'e',0,'n',0,'t',0};
                    static constexpr char WORKBK_W_B[] = {'W',0,'o',0,'r',0,'k',0,'b',0,'o',0,'o',0,'k',0};
                    static constexpr char BOOK_W_B[]   = {'B',0,'o',0,'o',0,'k',0,0,0};
                    static constexpr char PPT_W_B[]    = {'P',0,'o',0,'w',0,'e',0,'r',0,'P',0,'o',0,'i',0,'n',0,'t',0,' ',0,'D',0,'o',0,'c',0,'u',0,'m',0,'e',0,'n',0,'t',0};
                    static constexpr char MSP_W_B[]    = {'M',0,'S',0,'P',0,'r',0,'o',0,'j',0,'e',0,'c',0,'t',0};
                    static constexpr char MSI_W_B[]    = {'M',0,'S',0,'I',0,' ',0};
                    static constexpr std::string_view WORD_W   {WORD_W_B,   sizeof WORD_W_B};
                    static constexpr std::string_view WORKBK_W {WORKBK_W_B, sizeof WORKBK_W_B};
                    static constexpr std::string_view BOOK_W   {BOOK_W_B,   sizeof BOOK_W_B};
                    static constexpr std::string_view PPT_W    {PPT_W_B,    sizeof PPT_W_B};
                    static constexpr std::string_view MSP_W    {MSP_W_B,    sizeof MSP_W_B};
                    static constexpr std::string_view MSI_W    {MSI_W_B,    sizeof MSI_W_B};
                    if (view.find(WORD_W) != std::string_view::npos || view.find("WordDocument") != std::string_view::npos) {
                        return "application/msword";
                    }
                    if (view.find(WORKBK_W) != std::string_view::npos || view.find(BOOK_W) != std::string_view::npos
                        || view.find("Workbook") != std::string_view::npos || view.find("Book") != std::string_view::npos) {
                        return "application/vnd.ms-excel";
                    }
                    if (view.find(PPT_W) != std::string_view::npos || view.find("PowerPoint") != std::string_view::npos) {
                        return "application/vnd.ms-powerpoint";
                    }
                    if (view.find(MSI_W) != std::string_view::npos || view.find("MSI ") != std::string_view::npos) {
                        return "application/x-msi";
                    }
                    if (view.find(MSP_W) != std::string_view::npos || view.find("MSProject") != std::string_view::npos) {
                        return "application/vnd.ms-project";
                    }
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

        return std::string_view{};
    }

    std::string_view MimeDetector::detect(const std::filesystem::path& path) {
        std::ifstream file(path, std::ios::binary);
        if (!file) {
            return "application/octet-stream";
        }

        std::array<uint8_t, READ_BUFFER_SIZE> buffer{}; 
        file.read(reinterpret_cast<char*>(buffer.data()), buffer.size());
        const auto bytes_read = static_cast<size_t>(file.gcount());

        const std::string_view mime = detect(std::span(buffer.data(), bytes_read));

        // Fallback to extension database if binary sniffing was inconclusive
        if (mime.empty() || mime == "application/zip" || mime == "application/x-ole-storage" || mime == "application/x-riff") {
            std::string ext = path.extension().string();
            std::ranges::transform(ext, ext.begin(), [](const unsigned char char_code) -> char {
                return static_cast<char>(std::tolower(char_code));
            });

            // binary search with projection
            const auto it = std::ranges::lower_bound(
                global_extension_rules_span, 
                ext, 
                std::less<>{}, 
                &ExtensionRule::extension
            );

            if (it != global_extension_rules_span.end() && it->extension == ext) {
                bool conflict = false;
                if (!mime.empty() && it->mime != mime) {
                    for (const auto& rule : global_magic_rules_span) {
                        if (rule.mime == it->mime) {
                            conflict = true;
                            break;
                        }
                    }
                }
                
                if (!conflict) {
                    return it->mime;
                }
            }
        }
        
        if (mime.empty()) {
            return "application/octet-stream";
        }

        // this is a false positive, we only ever return data with static storage duration
        // NOLINTNEXTLINE(return-stack-address)
        return mime;
    }

} // namespace qadmimes
