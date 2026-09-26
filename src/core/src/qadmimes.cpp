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

    // Length of the MPEG audio frame whose header starts at `at`, or 0 if there is no valid header there
    static size_t mpeg_audio_frame_length(const std::span<const uint8_t> buffer, const size_t at) {
        static constexpr unsigned BITRATES[2][3][15] = {
            {{0, 32, 64, 96, 128, 160, 192, 224, 256, 288, 320, 352, 384, 416, 448},  // MPEG-1 layer I
             {0, 32, 48, 56, 64, 80, 96, 112, 128, 160, 192, 224, 256, 320, 384},     // MPEG-1 layer II
             {0, 32, 40, 48, 56, 64, 80, 96, 112, 128, 160, 192, 224, 256, 320}},     // MPEG-1 layer III
            {{0, 32, 48, 56, 64, 80, 96, 112, 128, 144, 160, 176, 192, 224, 256},     // MPEG-2/2.5 layer I
             {0, 8, 16, 24, 32, 40, 48, 56, 64, 80, 96, 112, 128, 144, 160},          // MPEG-2/2.5 layer II
             {0, 8, 16, 24, 32, 40, 48, 56, 64, 80, 96, 112, 128, 144, 160}}};        // MPEG-2/2.5 layer III
        static constexpr unsigned SAMPLE_RATES[3] = {44100, 48000, 32000};

        if (at + 4 > buffer.size() || buffer[at] != 0xff || (buffer[at + 1] & 0xe0) != 0xe0) {
            return 0;
        }
        const unsigned version = (buffer[at + 1] >> 3) & 3; // 0: MPEG-2.5, 1: reserved, 2: MPEG-2, 3: MPEG-1
        const unsigned layer = (buffer[at + 1] >> 1) & 3;   // 0: reserved, 1: III, 2: II, 3: I
        const unsigned bitrate_index = buffer[at + 2] >> 4;
        const unsigned rate_index = (buffer[at + 2] >> 2) & 3;
        const unsigned padding = (buffer[at + 2] >> 1) & 1;
        // free format (bitrate index 0) has no computable length and is left to the extension
        if (version == 1 || layer == 0 || bitrate_index == 0 || bitrate_index == 15 || rate_index == 3) {
            return 0;
        }

        const unsigned bitrate = BITRATES[version == 3 ? 0 : 1][3 - layer][bitrate_index] * 1000;
        const unsigned sample_rate = SAMPLE_RATES[rate_index] >> (version == 3 ? 0 : version == 2 ? 1 : 2);
        if (layer == 3) {
            return (12 * bitrate / sample_rate + padding) * 4;
        }
        const unsigned samples = (layer == 1 && version != 3) ? 72 : 144;
        return samples * bitrate / sample_rate + padding;
    }

    // Validates an MPEG audio stream without ID3: a well-formed frame header, followed by another
    // one when the buffer is long enough to hold it
    static bool sniff_mpeg_audio(const std::span<const uint8_t> buffer) {
        const size_t length = mpeg_audio_frame_length(buffer, 0);
        if (length == 0) {
            return false;
        }
        return length + 4 > buffer.size() || mpeg_audio_frame_length(buffer, length) != 0;
    }

    // Length of the ID3v2 tag at the start of the buffer, footer included, or 0 if there is none
    static size_t id3v2_length(const std::span<const uint8_t> buffer) {
        if (buffer.size() < 10 || std::memcmp(buffer.data(), "ID3", 3) != 0 || buffer[3] < 2 || buffer[3] > 4 ||
            buffer[4] == 0xff) {
            return 0;
        }
        size_t size = 0;
        for (size_t i = 6; i < 10; ++i) {
            if (buffer[i] & 0x80) {
                return 0;
            }
            size = (size << 7) | buffer[i];
        }
        const bool footer = buffer[3] == 4 && (buffer[5] & 0x10) != 0;
        return 10 + size + (footer ? 10 : 0);
    }

    // Audio formats that can carry an ID3v2 tag in front of their own header: the tag doesn't make them MPEG audio
    static bool fronted_by_id3(const std::string_view mime) {
        return mime == "audio/flac" || mime == "audio/x-ape" || mime == "audio/x-wavpack" || mime == "audio/x-tta" ||
               mime == "audio/x-musepack";
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
        size_t offset = 0;
        while (const size_t length = id3v2_length(buffer.subspan(offset))) {
            offset += length;
            if (offset >= buffer.size()) {
                return "audio/mpeg";
            }
        }
        if (offset > 0) {
            const std::string_view inner = match_rules(buffer.subspan(offset));
            return fronted_by_id3(inner) ? inner : "audio/mpeg";
        }
        return match_rules(buffer);
    }

    std::string_view MimeDetector::match_rules(const std::span<const uint8_t> buffer) {
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
                // a 12-bit frame sync alone matches any data starting with 0xFFFx
                if (match && rule.mime == "audio/mpeg" && !sniff_mpeg_audio(buffer)) {
                    match = false;
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
        auto bytes_read = static_cast<size_t>(file.gcount());

        // a cover makes an ID3v2 tag longer than the buffer: read what follows the tags from the file
        size_t offset = 0;
        for (size_t length = id3v2_length(std::span(buffer.data(), bytes_read)); length != 0;) {
            offset += length;
            std::array<uint8_t, 10> header{};
            file.clear();
            file.seekg(static_cast<std::streamoff>(offset));
            file.read(reinterpret_cast<char*>(header.data()), header.size());
            length = id3v2_length(std::span(header.data(), static_cast<size_t>(file.gcount())));
        }
        if (offset > 0) {
            file.clear();
            file.seekg(static_cast<std::streamoff>(offset));
            file.read(reinterpret_cast<char*>(buffer.data()), buffer.size());
            bytes_read = static_cast<size_t>(file.gcount());
            const std::string_view inner = match_rules(std::span(buffer.data(), bytes_read));
            return fronted_by_id3(inner) ? inner : "audio/mpeg";
        }

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
