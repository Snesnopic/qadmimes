#pragma once

#include <filesystem>
#include <string>
#include <span>
#include <string_view>

/**
 * @namespace qadmimes
 * @brief Main namespace for the Quick and Dirty Mimes library.
 */
namespace qadmimes {

    /**
     * @struct MagicRule
     * @brief Represents a single rule for magic byte detection.
     */
    struct MagicRule {
        size_t offset;           ///< Offset from the start of the file/buffer.
        std::string_view pattern; ///< Byte pattern to match.
        std::string_view mask;    ///< Optional bitmask for the pattern (empty if none).
        std::string_view mime;    ///< Associated MIME type.
    };

    /**
     * @class MimeDetector
     * @brief High-performance, zero-allocation MIME type detector.
     *
     * This class provides static methods to detect the MIME type of a file
     * or a memory buffer. It uses a combination of magic byte patterns,
     * deep container sniffing (ZIP, OLE, RIFF), and a massive extension database.
     */
    class MimeDetector {
    public:
        /**
         * @brief Detects the MIME type of a file given its path.
         * @param path The path to the file on disk.
         * @return A string_view pointing to the detected MIME type.
         *         Returns "application/octet-stream" if detection fails.
         * @note This method reads the first few KBs of the file for sniffing.
         */
        static std::string_view detect(const std::filesystem::path& path);

        /**
         * @brief Detects the MIME type from a memory buffer.
         * @param buffer A span of bytes representing the start of a file.
         * @return A string_view pointing to the detected MIME type.
         *         Returns "application/octet-stream" if detection fails.
         * @note Zero-allocation: the returned string_view points to static memory.
         */
        static std::string_view detect(std::span<const uint8_t> buffer);

    private:
        /**
         * @brief Internal helper to sniff container formats (ZIP, etc.).
         * @param buffer The input buffer.
         * @return The specific MIME type if identified, otherwise a generic container type.
         */
        static std::string_view sniff_container(std::span<const uint8_t> buffer);
    };

} // namespace qadmimes
