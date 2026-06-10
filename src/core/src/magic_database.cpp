#include <qadmimes.hpp>
#include <array>
#include <string_view>
#include <span>

using namespace std::string_view_literals;

namespace qadmimes {

    // Internal constexpr array for the rules. 
    static constexpr MagicRule global_magic_rules[] = {
        // --- IMAGES ---
        MagicRule{0, "\x89PNG\r\n\x1a\n"sv, ""sv, "image/png"sv},
        MagicRule{0, "\xff\xd8\xff"sv, ""sv, "image/jpeg"sv},
        MagicRule{0, "GIF87a"sv, ""sv, "image/gif"sv},
        MagicRule{0, "GIF89a"sv, ""sv, "image/gif"sv},
        MagicRule{0, "RIFF"sv, ""sv, "application/x-riff"sv}, 
        MagicRule{0, "BM"sv, ""sv, "image/bmp"sv},
        MagicRule{0, "\x00\x00\x01\x00"sv, ""sv, "image/x-icon"sv},
        MagicRule{0, "\x00\x00\x02\x00"sv, ""sv, "image/x-icon"sv},
        MagicRule{0, "\x00\x00\x00\x0cJXL \r\n\x87\n"sv, ""sv, "image/jxl"sv},
        MagicRule{0, "\xff\x0a"sv, ""sv, "image/jxl"sv},
        MagicRule{0, "\x00\x00\x00\x0c\x6a\x50\x20\x20\x0d\x0a\x87\x0a"sv, ""sv, "image/jp2"sv},
        MagicRule{0, "\xff\x4f\xff\x51"sv, ""sv, "image/jp2"sv}, 
        MagicRule{0, "\xb1\x68\xde\x3a"sv, ""sv, "image/x-dcx"sv},
        MagicRule{0, "icns"sv, ""sv, "image/x-icns"sv},
        MagicRule{0, "II*\x00"sv, ""sv, "image/tiff"sv},
        MagicRule{0, "MM\x00*"sv, ""sv, "image/tiff"sv},
        MagicRule{0, "\x0a\x05\x01\x08"sv, ""sv, "image/x-pcx"sv},
        MagicRule{0, "\x0a\x02\x01\x01"sv, ""sv, "image/x-pcx"sv},
        MagicRule{0, "\x0a\x03\x01\x01"sv, ""sv, "image/x-pcx"sv},
        MagicRule{0, "gft\x01"sv, ""sv, "application/x-gft"sv},
        
        // --- AUDIO ---
        MagicRule{0, "fLaC"sv, ""sv, "audio/flac"sv},
        MagicRule{0, "ID3"sv, ""sv, "audio/mpeg"sv},
        MagicRule{0, "\xff\xf0"sv, "\xff\xf0"sv, "audio/mpeg"sv}, 
        MagicRule{0, "OggS"sv, ""sv, "audio/ogg"sv},
        MagicRule{0, "MAC "sv, ""sv, "audio/x-ape"sv},
        MagicRule{0, "wvpk"sv, ""sv, "audio/x-wavpack"sv},
        MagicRule{0, "TTA1"sv, ""sv, "audio/x-tta"sv},
        MagicRule{0, "DSD "sv, ""sv, "audio/x-dsf"sv},
        MagicRule{0, "FRM8"sv, ""sv, "audio/x-dff"sv},
        MagicRule{0, "MP+\x07"sv, ""sv, "audio/x-musepack"sv},
        MagicRule{0, "MP+"sv, ""sv, "audio/x-musepack"sv},
        
        // --- VIDEO / CONTAINERS ---
        MagicRule{0, "\x1a\x45\xdf\xa3"sv, ""sv, "video/x-matroska"sv},
        MagicRule{4, "ftyp"sv, ""sv, "video/mp4"sv},
        MagicRule{0, "\x30\x26\xb2\x75\x8e\x66\xcf\x11"sv, ""sv, "video/x-ms-asf"sv}, 
        MagicRule{0, "FLV\x01"sv, ""sv, "video/x-flv"sv},
        MagicRule{0, "CWS"sv, ""sv, "application/x-shockwave-flash"sv},
        MagicRule{0, "FWS"sv, ""sv, "application/x-shockwave-flash"sv},
        
        // --- DOCUMENTS ---
        MagicRule{0, "%PDF-"sv, ""sv, "application/pdf"sv},
        MagicRule{0, "PK\x03\x04"sv, ""sv, "application/zip"sv}, 
        MagicRule{0, "\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"sv, ""sv, "application/x-ole-storage"sv},
        MagicRule{0, "<?xml"sv, ""sv, "application/xml"sv}, 
        MagicRule{0, "{\""sv, ""sv, "application/json"sv},
        MagicRule{0, "vCard"sv, ""sv, "text/vcard"sv},
        
        // --- ARCHIVES ---
        MagicRule{0, "\x1f\x8b"sv, ""sv, "application/gzip"sv},
        MagicRule{0, "BZh"sv, ""sv, "application/x-bzip2"sv},
        MagicRule{0, "\xfd\x37\x7a\x58\x5a\x00"sv, ""sv, "application/x-xz"sv},
        MagicRule{0, "7z\xbc\xaf\x27\x1c"sv, ""sv, "application/x-7z-compressed"sv},
        MagicRule{0, "Rar!\x1a\x07\x00"sv, ""sv, "application/vnd.rar"sv}, 
        MagicRule{0, "Rar!\x1a\x07\x01"sv, ""sv, "application/vnd.rar"sv}, 
        MagicRule{0, "sknz"sv, ""sv, "application/x-kanzi"sv},
        MagicRule{0, "\x28\xb5\x2f\xfd"sv, ""sv, "application/zstd"sv},
        MagicRule{257, "ustar"sv, ""sv, "application/x-tar"sv},
        MagicRule{0, "]\x00\x00\x80\x00"sv, ""sv, "application/x-lzma"sv},
        MagicRule{0, "070707"sv, ""sv, "application/x-cpio"sv},
        MagicRule{0, "070701"sv, ""sv, "application/x-cpio"sv},
        MagicRule{0, "070702"sv, ""sv, "application/x-cpio"sv},
        MagicRule{0, "!<arch>\n"sv, ""sv, "application/x-archive"sv},
        MagicRule{0, "RDB\x00"sv, ""sv, "application/x-rdb"sv},
        MagicRule{32769, "CD001"sv, ""sv, "application/x-iso9660-image"sv},
        MagicRule{34817, "CD001"sv, ""sv, "application/x-iso9660-image"sv},
        MagicRule{36865, "CD001"sv, ""sv, "application/x-iso9660-image"sv},
        MagicRule{0, "MSWIM\x00\x00\x00"sv, ""sv, "application/x-ms-wim"sv},
        MagicRule{0, "MSCF"sv, ""sv, "application/vnd.ms-cab-compressed"sv},
        
        // --- EXECUTABLES ---
        MagicRule{0, "MZ"sv, ""sv, "application/x-msdownload"sv},
        MagicRule{0, "\x7f\x45\x4c\x46"sv, ""sv, "application/x-executable"sv},
        
        // --- SPECIALIZED ---
        MagicRule{0, "\x06\x06\xed\xf5\xd1\x4a\x1d\x91"sv, ""sv, "application/vnd.fdsn.mseed"sv},
        MagicRule{0, "SQLite format "sv, ""sv, "application/vnd.sqlite3"sv}
    };

    extern const std::span<const MagicRule> global_magic_rules_span = global_magic_rules;

    struct ExtensionRule {
        std::string_view extension;
        std::string_view mime;
    };

    // Huge extension database from MegaMimes + original fallbacks
    static constexpr ExtensionRule global_extension_rules[] = {
        // --- Core Fallbacks ---
        ExtensionRule{ ".docx"sv, "application/vnd.openxmlformats-officedocument.wordprocessingml.document"sv },
        ExtensionRule{ ".xlsx"sv, "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"sv },
        ExtensionRule{ ".pptx"sv, "application/vnd.openxmlformats-officedocument.presentationml.presentation"sv },
        ExtensionRule{ ".odt"sv,  "application/vnd.oasis.opendocument.text"sv },
        ExtensionRule{ ".ods"sv,  "application/vnd.oasis.opendocument.spreadsheet"sv },
        ExtensionRule{ ".epub"sv, "application/epub+zip"sv },
        ExtensionRule{ ".apk"sv,  "application/vnd.android.package-archive"sv },
        ExtensionRule{ ".jar"sv,  "application/java-archive"sv },
        ExtensionRule{ ".mkv"sv,  "video/x-matroska"sv },
        ExtensionRule{ ".webm"sv, "video/webm"sv },
        ExtensionRule{ ".wav"sv,  "audio/wav"sv },
        ExtensionRule{ ".webp"sv, "image/webp"sv },
        ExtensionRule{ ".doc"sv,  "application/msword"sv },
        ExtensionRule{ ".xls"sv,  "application/vnd.ms-excel"sv },
        ExtensionRule{ ".ppt"sv,  "application/vnd.ms-powerpoint"sv },
        ExtensionRule{ ".mpp"sv,  "application/vnd.ms-project"sv },
        ExtensionRule{ ".vst"sv,  "image/x-tga"sv },
        ExtensionRule{ ".msi"sv,  "application/x-msi"sv },
        ExtensionRule{ ".msp"sv,  "application/x-msi"sv },
        ExtensionRule{ ".mst"sv,  "application/x-msi"sv },
        ExtensionRule{ ".mseed"sv, "application/vnd.fdsn.mseed"sv },
        ExtensionRule{ ".sqlite"sv, "application/vnd.sqlite3"sv },
        ExtensionRule{ ".db"sv,    "application/vnd.sqlite3"sv },
        ExtensionRule{ ".7z"sv,    "application/x-7z-compressed"sv },
        ExtensionRule{ ".rar"sv,   "application/vnd.rar"sv },
        ExtensionRule{ ".gz"sv,    "application/gzip"sv },
        ExtensionRule{ ".tgz"sv,   "application/gzip"sv },
        ExtensionRule{ ".bz2"sv,   "application/x-bzip2"sv },
        ExtensionRule{ ".xz"sv,    "application/x-xz"sv },
        ExtensionRule{ ".tar"sv,   "application/x-tar"sv },
        ExtensionRule{ ".wim"sv,   "application/x-ms-wim"sv },
        ExtensionRule{ ".ora"sv,   "image/openraster"sv },
        ExtensionRule{ ".dwfx"sv,  "model/vnd.dwfx+xps"sv },
        ExtensionRule{ ".3mf"sv,   "application/vnd.ms-package.3dmanufacturing-3dmodel+xml"sv },
        ExtensionRule{ ".kmz"sv,   "application/vnd.google-earth.kmz"sv },
        ExtensionRule{ ".jxl"sv,   "image/jxl"sv },
        ExtensionRule{ ".svg"sv,   "image/svg+xml"sv },
        ExtensionRule{ ".json"sv,  "application/json"sv },
        ExtensionRule{ ".xml"sv,   "application/xml"sv },
        ExtensionRule{ ".vcf"sv,   "text/vcard"sv },
        ExtensionRule{ ".mp3"sv,   "audio/mpeg"sv },
        ExtensionRule{ ".m4a"sv,   "video/mp4"sv },
        ExtensionRule{ ".mp4"sv,   "video/mp4"sv },
        ExtensionRule{ ".zip"sv,   "application/zip"sv },
                // --- Absorbed from MegaMimes ---
        ExtensionRule{ ".1"sv, "text/troff"sv }, // Roff Manpage
        ExtensionRule{ ".3ds"sv, "image/x-3ds"sv }, // 3DS
        ExtensionRule{ ".3fr"sv, "image/x-raw-hasselblad"sv }, // Hasselblad raw image
        ExtensionRule{ ".3g2"sv, "video/3gpp2"sv }, // 3G2
        ExtensionRule{ ".3gp"sv, "video/3gpp"sv }, // 3GP
        ExtensionRule{ ".3mf"sv, "application/vnd.ms-package.3dmanufacturing-3dmodel+xml"sv }, // 3MF 3D Manufacturing Format
        ExtensionRule{ ".4th"sv, "text/x-forth"sv }, // Forth source code
        ExtensionRule{ ".669"sv, "audio/x-mod"sv }, // Module Music Formats (Mods)
        ExtensionRule{ ".6pl"sv, "text/x-perl"sv }, // Perl 6
        ExtensionRule{ ".7z"sv, "application/x-7z-compressed"sv }, // 7-zip archive
        ExtensionRule{ ".8svx"sv, "audio/8svx"sv }, // 8-Bit Sampled Voice
        ExtensionRule{ ".ML"sv, "text/x-ocaml"sv }, // Standard ML
        ExtensionRule{ ".MYD"sv, "application/x-mysql-misam-data"sv }, // MySQL MISAM Data
        ExtensionRule{ ".MYI"sv, "application/x-mysql-misam-compressed-index"sv }, // MySQL MISAM Compressed Index
        ExtensionRule{ ".R"sv, "text/x-rsrc"sv }, // R
        ExtensionRule{ ".TIF"sv, "image/tiff"sv }, // TIFF Uncompressed File with Exif Metadata
        ExtensionRule{ ".XXX"sv, "application/octet-stream"sv }, // Template:File Format/Preload
        ExtensionRule{ ".Z"sv, "application/x-compress"sv }, // Compress
        ExtensionRule{ ".aa"sv, "audio/x-pn-audibleaudio"sv }, // Audible.Com File Format
        ExtensionRule{ ".ac3"sv, "audio/ac3"sv }, // Dolby Digital AC-3
        ExtensionRule{ ".acsm"sv, "application/vnd.adobe.adept+xml"sv }, // Adobe Content Server Message File
        ExtensionRule{ ".ada"sv, "text/x-ada"sv }, // Ada source code
        ExtensionRule{ ".adf"sv, "multipart/appledouble"sv }, // AppleDouble
        ExtensionRule{ ".afa"sv, "application/x-astrotite-afa"sv }, // Astrotite
        ExtensionRule{ ".afm"sv, "application/x-font-adobe-metric"sv }, // Adobe Font Metric
        ExtensionRule{ ".ai"sv, "application/illustrator"sv }, // Adobe Illustrator Artwork
        ExtensionRule{ ".aif"sv, "audio/x-aiff"sv }, // Audio Interchange File Format
        ExtensionRule{ ".aifc"sv, "audio/x-aiff"sv }, // Audio Interchange File Format (compressed)
        ExtensionRule{ ".aiff"sv, "audio/x-aiff"sv }, // AIFF
        ExtensionRule{ ".aj"sv, "text/x-aspectj"sv }, // AspectJ source code
        ExtensionRule{ ".amr"sv, "audio/amr"sv }, // AMR, Adaptive Multi-Rate Speech Codec
        ExtensionRule{ ".anim"sv, "text/x-yaml"sv }, // Unity3D Asset
        ExtensionRule{ ".anpa"sv, "text/vnd.iptc.anpa"sv }, // American Newspaper Publishers Association Wire Feeds
        ExtensionRule{ ".ans"sv, "text/plain"sv }, // 7-bit ANSI Text
        ExtensionRule{ ".apl"sv, "text/apl"sv }, // APL
        ExtensionRule{ ".apng"sv, "image/vnd.mozilla.apng"sv }, // Animated Portable Network Graphics
        ExtensionRule{ ".applescript"sv, "text/x-applescript"sv }, // AppleScript source code
        ExtensionRule{ ".apt"sv, "application/vnd.lotus-approach"sv }, // Lotus Approach View File
        ExtensionRule{ ".arw"sv, "image/x-raw-sony"sv }, // Sony raw image
        ExtensionRule{ ".as"sv, "text/x-actionscript"sv }, // ActionScript source code
        ExtensionRule{ ".asc"sv, "text/plain"sv }, // 7-bit ASCII Text
        ExtensionRule{ ".asciidoc"sv, "text/x-asciidoc"sv }, // Asciidoc source code
        ExtensionRule{ ".asf"sv, "application/vnd.ms-asf"sv }, // Advanced Systems Format
        ExtensionRule{ ".asice"sv, "application/vnd.etsi.asic-e+zip"sv }, // Extended Associated Signature Container
        ExtensionRule{ ".asics"sv, "application/vnd.etsi.asic-s+zip"sv }, // Simple Associated Signature Container
        ExtensionRule{ ".asn"sv, "text/x-ttcn-asn"sv }, // ASN.1
        ExtensionRule{ ".asp"sv, "application/x-aspx"sv }, // ASP
        ExtensionRule{ ".aspx"sv, "text/aspdotnet"sv }, // ASP .NET
        ExtensionRule{ ".asy"sv, "text/x-spreadsheet"sv }, // LTspice Symbol
        ExtensionRule{ ".atom"sv, "application/atom+xml"sv }, // Atom
        ExtensionRule{ ".au"sv, "audio/basic"sv }, // uLaw/AU Audio File
        ExtensionRule{ ".avi"sv, "video/msvideo"sv }, // AVI (Audio Video Interleaved) File Format
        ExtensionRule{ ".awb"sv, "audio/amr-wb"sv }, // Adaptive Multi-Rate Wideband Audio
        ExtensionRule{ ".awk"sv, "text/x-awk"sv }, // AWK script
        ExtensionRule{ ".axc"sv, "text/plain"sv }, // Axc
        ExtensionRule{ ".axx"sv, "application/x-axcrypt"sv }, // AxCrypt
        ExtensionRule{ ".b"sv, "text/x-brainfuck"sv }, // Brainfuck
        ExtensionRule{ ".b6z"sv, "application/x-b6z-compressed"sv }, // B6Z
        ExtensionRule{ ".bas"sv, "text/x-basic"sv }, // Basic source code
        ExtensionRule{ ".bay"sv, "image/x-raw-casio"sv }, // Casio raw image
        ExtensionRule{ ".bik"sv, "video/vnd.radgamettools.bink"sv }, // Bink Video
        ExtensionRule{ ".bin"sv, "application/x-macbinary"sv }, // MacBinary
        ExtensionRule{ ".bmp"sv, "image/bmp"sv }, // Windows bitmap
        ExtensionRule{ ".bpg"sv, "image/x-bpg"sv }, // Better Portable Graphics
        ExtensionRule{ ".bpm"sv, "application/bizagi-modeler"sv }, // BizAgi Process Modeler
        ExtensionRule{ ".bsp"sv, "model/vnd.valve.source.compiled-map"sv }, // BSP
        ExtensionRule{ ".btf"sv, "image/tiff"sv }, // BigTIFF
        ExtensionRule{ ".bw"sv, "image/x-sgi-bw"sv }, // Silicon Graphics Image
        ExtensionRule{ ".bz2"sv, "application/x-bzip2"sv }, // Bzip2
        ExtensionRule{ ".c"sv, "text/x-csrc"sv }, // C source code
        ExtensionRule{ ".cab"sv, "application/vnd.ms-cab-compressed"sv }, // Cabinet
        ExtensionRule{ ".cabal"sv, "text/x-haskell"sv }, // Cabal Config
        ExtensionRule{ ".cap"sv, "application/vnd.tcpdump.pcap"sv }, // pcap Packet Capture
        ExtensionRule{ ".cbl"sv, "text/x-cobol"sv }, // COBOL source code
        ExtensionRule{ ".cbor"sv, "application/cbor"sv }, // Concise Binary Object Representation container
        ExtensionRule{ ".cbz"sv, "application/x-cbr"sv }, // Comic Book Archive
        ExtensionRule{ ".cca"sv, "application/octet-stream"sv }, // cc:Mail Archive Email Format
        ExtensionRule{ ".cda"sv, "application/x-cdf"sv }, // CD Audio
        ExtensionRule{ ".cdf"sv, "application/x-netcdf"sv }, // netCDF-3 Classic
        ExtensionRule{ ".cdx"sv, "chemical/x-cdx"sv }, // Chemical Draw Exchange Format
        ExtensionRule{ ".cfm"sv, "text/x-coldfusion"sv }, // ColdFusion source code
        ExtensionRule{ ".cfs"sv, "application/x-cfs-compressed"sv }, // Compact File Set
        ExtensionRule{ ".cgi"sv, "text/x-cgi"sv }, // CGI script
        ExtensionRule{ ".cgm"sv, "image/cgm"sv }, // Computer Graphics Metafile
        ExtensionRule{ ".chm"sv, "application/vnd.ms-htmlhelp"sv }, // Microsoft Compiled HTML Help
        ExtensionRule{ ".chrt"sv, "application/x-kchart"sv }, // KChart File
        ExtensionRule{ ".chs"sv, "text/x-haskell"sv }, // C2hs Haskell
        ExtensionRule{ ".cif"sv, "chemical/x-cif"sv }, // CIF
        ExtensionRule{ ".ck"sv, "text/x-java"sv }, // ChucK
        ExtensionRule{ ".cl"sv, "text/x-common-lisp"sv }, // Common Lisp source code
        ExtensionRule{ ".class"sv, "application/x-java"sv }, // Java Class File
        ExtensionRule{ ".clj"sv, "text/x-clojure"sv }, // Clojure source code
        ExtensionRule{ ".cls"sv, "text/x-vbasic"sv }, // Visual basic source code
        ExtensionRule{ ".cmake"sv, "text/x-cmake"sv }, // CMake
        ExtensionRule{ ".cml"sv, "chemical/x-cml"sv }, // CML
        ExtensionRule{ ".cob"sv, "text/x-cobol"sv }, // COBOL
        ExtensionRule{ ".cod"sv, "image/cis-cod"sv }, // Lightning Strike
        ExtensionRule{ ".coffee"sv, "application/vnd.coffeescript"sv }, // CoffeeScript
        ExtensionRule{ ".cp"sv, "text/x-pascal"sv }, // Component Pascal
        ExtensionRule{ ".cpio"sv, "application/x-cpio"sv }, // UNIX CPIO Archive
        ExtensionRule{ ".cpp"sv, "text/x-c++src"sv }, // C++ source code
        ExtensionRule{ ".cr"sv, "text/x-crystal"sv }, // Crystal
        ExtensionRule{ ".crw"sv, "image/x-canon-crw"sv }, // Camera Image File Format
        ExtensionRule{ ".crx"sv, "application/x-chrome-package"sv }, // Chrome Extension Package
        ExtensionRule{ ".cs"sv, "text/x-csharp"sv }, // C# source code
        ExtensionRule{ ".cshtml"sv, "text/html"sv }, // HTML+Razor
        ExtensionRule{ ".cson"sv, "text/x-coffeescript"sv }, // CSON
        ExtensionRule{ ".csr"sv, "application/pkcs10"sv }, // PKCS10
        ExtensionRule{ ".css"sv, "text/css"sv }, // Cascading Style Sheet
        ExtensionRule{ ".csv"sv, "text/csv"sv }, // Comma Separated Values
        ExtensionRule{ ".csvs"sv, "text/csv-schema"sv }, // CSV Schema
        ExtensionRule{ ".cu"sv, "text/x-c++src"sv }, // Cuda
        ExtensionRule{ ".cur"sv, "image/x-win-bitmap"sv }, // Microsoft Windows Cursor
        ExtensionRule{ ".cwl"sv, "text/x-yaml"sv }, // Common Workflow Language
        ExtensionRule{ ".cy"sv, "text/javascript"sv }, // Cycript
        ExtensionRule{ ".d"sv, "text/x-d"sv }, // D source code
        ExtensionRule{ ".dae"sv, "text/xml"sv }, // COLLADA
        ExtensionRule{ ".dart"sv, "application/dart"sv }, // Dart
        ExtensionRule{ ".dat"sv, "application/dbase"sv }, // MapInfo Data File (DAT)
        ExtensionRule{ ".db"sv, "application/x-sqlite3"sv }, // SQLite Database File Format
        ExtensionRule{ ".dbf"sv, "application/x-dbf"sv }, // dBASE Table File Format (DBF)
        ExtensionRule{ ".dcm"sv, "application/dicom"sv }, // Digital Imaging and Communications in Medicine File Format
        ExtensionRule{ ".dcr"sv, "application/x-director"sv }, // Shockwave (Director)
        ExtensionRule{ ".dcx"sv, "image/x-dcx"sv }, // Multipage Zsoft Paintbrush Bitmap Graphics
        ExtensionRule{ ".deb"sv, "application/vnd.debian.binary-package"sv }, // Deb
        ExtensionRule{ ".der"sv, "application/x-x509-ca-cert"sv }, // DER encoded certificate
        ExtensionRule{ ".dex"sv, "application/x-dex"sv }, // Dalvik Executable Format
        ExtensionRule{ ".dgc"sv, "application/x-dgc-compressed"sv }, // DGCA
        ExtensionRule{ ".diff"sv, "text/x-diff"sv }, // Diff
        ExtensionRule{ ".dir"sv, "application/x-director"sv }, // Shockwave Movie
        ExtensionRule{ ".dita"sv, "application/dita+xml;format=topic"sv }, // DITA Topic
        ExtensionRule{ ".ditamap"sv, "application/dita+xml;format=map"sv }, // DITA Map
        ExtensionRule{ ".ditaval"sv, "application/dita+xml;format=val"sv }, // DITA Conditional Processing Profile
        ExtensionRule{ ".diz"sv, "text/plain"sv }, // FILE ID.DIZ
        ExtensionRule{ ".djv"sv, "image/vnd.djvu"sv }, // Secure DjVU
        ExtensionRule{ ".djvu"sv, "image/vnd.djvu"sv }, // DjVu
        ExtensionRule{ ".dll"sv, "application/octet-stream"sv }, // Windows Portable Executable
        ExtensionRule{ ".dls"sv, "audio/dls"sv }, // Downloadable Sounds Audio
        ExtensionRule{ ".dmg"sv, "application/x-apple-diskimage"sv }, // Apple Disk Image
        ExtensionRule{ ".dng"sv, "image/x-raw-adobe"sv }, // Adobe Digital Negative
        ExtensionRule{ ".doc"sv, "application/msword"sv }, // Microsoft Word
        ExtensionRule{ ".dockerfile"sv, "text/x-dockerfile"sv }, // Dockerfile
        ExtensionRule{ ".docm"sv, "application/vnd.ms-word.document.macroenabled.12"sv }, // Office Open XML Document (macro-enabled)
        ExtensionRule{ ".docx"sv, "application/vnd.openxmlformats-officedocument.wordprocessingml.document"sv }, // OOXML Format Family -- ISO/IEC 29500 and ECMA 376
        ExtensionRule{ ".dotm"sv, "application/vnd.ms-word.template.macroenabled.12"sv }, // Office Open XML Document Template (macro-enabled)
        ExtensionRule{ ".dotx"sv, "application/vnd.openxmlformats-officedocument.wordprocessingml.template"sv }, // Office Open XML Document Template
        ExtensionRule{ ".dpx"sv, "image/x-dpx"sv }, // Digital Moving-Picture Exchange (DPX), Version 2.0
        ExtensionRule{ ".drc"sv, "video/x-dirac"sv }, // Ogg Packaged Dirac Video
        ExtensionRule{ ".druby"sv, "text/x-ruby"sv }, // Mirah
        ExtensionRule{ ".dtd"sv, "application/xml-dtd"sv }, // XML Document Type Definition (DTD)
        ExtensionRule{ ".dts"sv, "audio/vnd.dts"sv }, // DTS Coherent Acoustics (DCA) Audio
        ExtensionRule{ ".dv"sv, "video/dv"sv }, // Digital Video
        ExtensionRule{ ".dvi"sv, "application/x-dvi"sv }, // DVI (Device Independent File Format)
        ExtensionRule{ ".dwfx"sv, "model/vnd.dwfx+xps"sv }, // AutoCAD Design Web Format
        ExtensionRule{ ".dwg"sv, "image/vnd.dwg"sv }, // AutoCad Drawing
        ExtensionRule{ ".dwl"sv, "application/octet-stream"sv }, // AutoCAD Database File Locking Information
        ExtensionRule{ ".dx"sv, "application/dec-dx."sv }, // DEC Data Exchange File
        ExtensionRule{ ".dxb"sv, "image/vnd.dxb"sv }, // AutoCAD DXF simplified Binary
        ExtensionRule{ ".dxf"sv, "image/vnd.dxf"sv }, // AutoCAD DXF
        ExtensionRule{ ".dylan"sv, "text/x-dylan"sv }, // Dylan
        ExtensionRule{ ".e"sv, "text/x-eiffel"sv }, // Eiffel source code
        ExtensionRule{ ".eb"sv, "text/x-python"sv }, // Easybuild
        ExtensionRule{ ".ebnf"sv, "text/x-ebnf"sv }, // EBNF
        ExtensionRule{ ".ebuild"sv, "text/x-sh"sv }, // Gentoo Ebuild
        ExtensionRule{ ".ecl"sv, "text/x-ecl"sv }, // ECL
        ExtensionRule{ ".eclass"sv, "text/x-sh"sv }, // Gentoo Eclass
        ExtensionRule{ ".ecr"sv, "text/html"sv }, // HTML+ECR
        ExtensionRule{ ".edc"sv, "application/json"sv }, // Edje Data Collection
        ExtensionRule{ ".edn"sv, "text/x-clojure"sv }, // edn
        ExtensionRule{ ".eex"sv, "text/html"sv }, // HTML+EEX
        ExtensionRule{ ".el"sv, "text/x-emacs-lisp"sv }, // Emacs Lisp source code
        ExtensionRule{ ".elc"sv, "application/x-elc"sv }, // Emacs Lisp bytecode
        ExtensionRule{ ".elm"sv, "text/x-elm"sv }, // Elm
        ExtensionRule{ ".em"sv, "text/x-coffeescript"sv }, // EmberScript
        ExtensionRule{ ".emf"sv, "image/emf"sv }, // Enhanced Metafile
        ExtensionRule{ ".eml"sv, "message/rfc822"sv }, // Internet e-mail message format
        ExtensionRule{ ".enr"sv, "application/x-endnote-refer"sv }, // EndNote Import File
        ExtensionRule{ ".ens"sv, "application/x-endnote-style"sv }, // EndNote Style File
        ExtensionRule{ ".enz"sv, "application/x-endnote-connect"sv }, // EndNote Connection File
        ExtensionRule{ ".eot"sv, "application/vnd.ms-fontobject"sv }, // Embedded OpenType
        ExtensionRule{ ".epj"sv, "application/json"sv }, // Ecere Projects
        ExtensionRule{ ".eps"sv, "application/postscript"sv }, // Encapsulated PostScript (EPS) File Format, Version 3.x
        ExtensionRule{ ".epub"sv, "application/epub+zip"sv }, // Electronic Publication
        ExtensionRule{ ".eq"sv, "text/x-csharp"sv }, // EQ
        ExtensionRule{ ".erb"sv, "application/x-erb"sv }, // HTML+ERB
        ExtensionRule{ ".erf"sv, "image/x-raw-epson"sv }, // Epson raw image
        ExtensionRule{ ".erl"sv, "text/x-erlang"sv }, // Erlang source code
        ExtensionRule{ ".es"sv, "application/ecmascript"sv }, // ECMAScript
        ExtensionRule{ ".exe"sv, "application/x-dosexec"sv }, // DOS/Windows executable (EXE)
        ExtensionRule{ ".exp"sv, "text/x-expect"sv }, // Expect Script
        ExtensionRule{ ".f"sv, "text/x-fortran"sv }, // Fortran source code
        ExtensionRule{ ".f4a"sv, "video/mp4"sv }, // MPEG-4 Media File
        ExtensionRule{ ".f4m"sv, "application/f4m"sv }, // F4M
        ExtensionRule{ ".f90"sv, "text/x-fortran"sv }, // Fortran
        ExtensionRule{ ".factor"sv, "text/x-factor"sv }, // Factor
        ExtensionRule{ ".fb2"sv, "application/x-fictionbook+xml"sv }, // FictionBook document
        ExtensionRule{ ".fdf"sv, "application/vnd.fdf"sv }, // Forms Data Format
        ExtensionRule{ ".fff"sv, "image/x-raw-imacon"sv }, // Imacon raw image
        ExtensionRule{ ".fh"sv, "image/x-freehand"sv }, // FreeHand image
        ExtensionRule{ ".fig"sv, "application/x-matlab-data"sv }, // Matlab figure
        ExtensionRule{ ".fits"sv, "image/fits"sv }, // Flexible Image Transport System
        ExtensionRule{ ".flac"sv, "audio/flac"sv }, // FLAC (Free Lossless Audio Codec), Version 1.1.2
        ExtensionRule{ ".flif"sv, "image/flif"sv }, // Free Lossless Image Format (FLIF)
        ExtensionRule{ ".flv"sv, "video/x-flv"sv }, // FLV
        ExtensionRule{ ".fm"sv, "application/vnd.framemaker"sv }, // FrameMaker
        ExtensionRule{ ".fmz"sv, "application/octet-stream"sv }, // form*Z Project File
        ExtensionRule{ ".folio"sv, "application/vnd.adobe.folio+zip"sv }, // Folio
        ExtensionRule{ ".fp7"sv, "application/x-filemaker"sv }, // FileMaker Pro 7
        ExtensionRule{ ".fpx"sv, "image/vnd.fpx"sv }, // FlashPix
        ExtensionRule{ ".fref"sv, "text/plain"sv }, // Freenet node reference
        ExtensionRule{ ".fs"sv, "text/x-fsharp"sv }, // F#
        ExtensionRule{ ".fth"sv, "text/x-forth"sv }, // Forth
        ExtensionRule{ ".g3"sv, "image/g3fax"sv }, // CCITT Group 3
        ExtensionRule{ ".gbr"sv, "application/vnd.gerber"sv }, // Gerber Format
        ExtensionRule{ ".gca"sv, "application/x-gca-compressed"sv }, // GCA
        ExtensionRule{ ".gf"sv, "text/x-haskell"sv }, // Grammatical Framework
        ExtensionRule{ ".ggb"sv, "application/vnd.geogebra.file"sv }, // Ggb
        ExtensionRule{ ".gif"sv, "image/gif"sv }, // Graphics Interchange Format
        ExtensionRule{ ".gitconfig"sv, "text/x-properties"sv }, // Git Config
        ExtensionRule{ ".gitignore"sv, "text/x-sh"sv }, // Ignore List
        ExtensionRule{ ".glf"sv, "text/x-tcl"sv }, // Glyph
        ExtensionRule{ ".gml"sv, "application/gml+xml"sv }, // Geography Markup Language
        ExtensionRule{ ".gn"sv, "text/x-python"sv }, // GN
        ExtensionRule{ ".gnumeric"sv, "application/x-gnumeric"sv }, // Gnumeric
        ExtensionRule{ ".go"sv, "text/x-go"sv }, // Go source code
        ExtensionRule{ ".grb"sv, "application/x-grib"sv }, // General Regularly-distributed Information in Binary form
        ExtensionRule{ ".groovy"sv, "text/x-groovy"sv }, // Groovy source code
        ExtensionRule{ ".gsp"sv, "application/x-jsp"sv }, // Groovy Server Pages
        ExtensionRule{ ".gtar"sv, "application/x-gtar"sv }, // GNU tar Compressed File Archive (GNU Tape Archive)
        ExtensionRule{ ".gz"sv, "application/gzip"sv }, // Gzip Compressed Archive
        ExtensionRule{ ".h"sv, "text/x-chdr"sv }, // C source code header
        ExtensionRule{ ".haml"sv, "text/x-haml"sv }, // HAML source code
        ExtensionRule{ ".hcl"sv, "text/x-ruby"sv }, // HCL
        ExtensionRule{ ".hdf"sv, "application/x-hdf"sv }, // Hierarchical Data Format File
        ExtensionRule{ ".hdp"sv, "image/vnd.ms-photo"sv }, // HD Photo, Version 1.0 (Windows Media Photo)
        ExtensionRule{ ".hdr"sv, "image/vnd.radiance"sv }, // Radiance HDR
        ExtensionRule{ ".hh"sv, "application/x-httpd-php"sv }, // Hack
        ExtensionRule{ ".hpgl"sv, "application/vnd.hp-hpgl"sv }, // Hewlett Packard Graphics Language
        ExtensionRule{ ".hpp"sv, "text/x-c++hdr"sv }, // C++ source code header
        ExtensionRule{ ".hqx"sv, "application/mac-binhex"sv }, // BinHex
        ExtensionRule{ ".hs"sv, "text/x-haskell"sv }, // Haskell source code
        ExtensionRule{ ".htm"sv, "text/html"sv }, // Hypertext Markup Language
        ExtensionRule{ ".html"sv, "text/html"sv }, // HyperText Markup Language
        ExtensionRule{ ".http"sv, "message/http"sv }, // HTTP
        ExtensionRule{ ".hx"sv, "text/x-haxe"sv }, // Haxe source code
        ExtensionRule{ ".ibooks"sv, "application/x-ibooks+zip"sv }, // Apple iBook format
        ExtensionRule{ ".ico"sv, "image/vnd.microsoft.icon"sv }, // ICO
        ExtensionRule{ ".ics"sv, "text/calendar"sv }, // Internet Calendar and Scheduling format
        ExtensionRule{ ".idl"sv, "text/x-idl"sv }, // Inteface Definition Language
        ExtensionRule{ ".idml"sv, "application/vnd.adobe.indesign-idml-package"sv }, // IDML
        ExtensionRule{ ".igs"sv, "model/iges"sv }, // Initial Graphics Exchange Specification Format
        ExtensionRule{ ".iiq"sv, "image/x-raw-phaseone"sv }, // Phase One raw image
        ExtensionRule{ ".indd"sv, "application/x-adobe-indesign"sv }, // Adobe InDesign document
        ExtensionRule{ ".inf"sv, "application/inf"sv }, // Windows Setup File
        ExtensionRule{ ".ini"sv, "text/x-ini"sv }, // Configuration file
        ExtensionRule{ ".inx"sv, "application/x-adobe-indesign-interchange"sv }, // Adobe InDesign Interchange format
        ExtensionRule{ ".ipa"sv, "application/x-itunes-ipa"sv }, // Apple iOS IPA AppStore file
        ExtensionRule{ ".ipynb"sv, "application/json"sv }, // Jupyter Notebook
        ExtensionRule{ ".irclog"sv, "text/mirc"sv }, // IRC log
        ExtensionRule{ ".iso"sv, "application/x-iso9660-image"sv }, // ISO Disk Image File Format
        ExtensionRule{ ".itk"sv, "application/x-tcl"sv }, // Tcl script
        ExtensionRule{ ".j2c"sv, "image/x-jp2-codestream"sv }, // JPEG 2000 Codestream
        ExtensionRule{ ".jade"sv, "text/x-pug"sv }, // Pug
        ExtensionRule{ ".jar"sv, "application/java-archive"sv }, // Java Archive
        ExtensionRule{ ".java"sv, "text/x-java"sv }, // Java source code
        ExtensionRule{ ".jinja"sv, "text/x-django"sv }, // HTML+Django
        ExtensionRule{ ".jl"sv, "text/x-julia"sv }, // Julia
        ExtensionRule{ ".jls"sv, "image/jls"sv }, // JPEG-LS
        ExtensionRule{ ".jng"sv, "image/x-jng"sv }, // JPEG Network Graphics
        ExtensionRule{ ".jnilib"sv, "application/x-java-jnilib"sv }, // Java Native Library for OSX
        ExtensionRule{ ".jp2"sv, "image/jpx"sv }, // JPEG 2000
        ExtensionRule{ ".jpe"sv, "image/jpeg"sv }, // Raw JPEG Stream
        ExtensionRule{ ".jpf"sv, "image/jpx"sv }, // JPX (JPEG 2000 part 2)
        ExtensionRule{ ".jpg"sv, "image/jpeg"sv }, // Joint Photographic Experts Group
        ExtensionRule{ ".jpm"sv, "image/jpm"sv }, // JPEG 2000 Part 6 (JPM)
        ExtensionRule{ ".jq"sv, "application/json"sv }, // JSONiq
        ExtensionRule{ ".js"sv, "application/javascript"sv }, // JavaScript Source Code
        ExtensionRule{ ".json"sv, "application/json"sv }, // JSON (JavaScript Object Notation)
        ExtensionRule{ ".json-patch"sv, "application/json-patch+json"sv }, // JSON Patch
        ExtensionRule{ ".json5"sv, "application/json"sv }, // JSON5
        ExtensionRule{ ".jsonld"sv, "application/ld+json"sv }, // JSON-LD
        ExtensionRule{ ".jsp"sv, "application/x-jsp"sv }, // Java Server Pages
        ExtensionRule{ ".jsx"sv, "text/jsx"sv }, // JSX
        ExtensionRule{ ".jxr"sv, "image/jxr"sv }, // JPEG Extended Range
        ExtensionRule{ ".k25"sv, "image/x-raw-kodak"sv }, // Kodak raw image
        ExtensionRule{ ".kicad_pcb"sv, "text/x-common-lisp"sv }, // KiCad Layout
        ExtensionRule{ ".kid"sv, "text/xml"sv }, // Genshi
        ExtensionRule{ ".kil"sv, "application/x-killustrator"sv }, // KIllustrator File
        ExtensionRule{ ".kit"sv, "text/html"sv }, // Kit
        ExtensionRule{ ".kml"sv, "application/vnd.google-earth.kml+xml"sv }, // Keyhole Markup Language
        ExtensionRule{ ".kmz"sv, "application/vnd.google-earth.kmz"sv }, // Keyhole Markup Language (Container)
        ExtensionRule{ ".kpr"sv, "application/x-kpresenter"sv }, // KPresenter File
        ExtensionRule{ ".kra"sv, "application/x-krita"sv }, // Krita Document Format
        ExtensionRule{ ".ksp"sv, "application/x-kspread"sv }, // KSpread File
        ExtensionRule{ ".kt"sv, "text/x-kotlin"sv }, // Kotlin
        ExtensionRule{ ".ktx"sv, "image/ktx"sv }, // Khronos Texture File
        ExtensionRule{ ".kwd"sv, "application/x-kword"sv }, // KWord File
        ExtensionRule{ ".l"sv, "text/x-lex"sv }, // Lex/Flex source code
        ExtensionRule{ ".latex"sv, "application/x-latex"sv }, // LaTeX Source Document
        ExtensionRule{ ".latte"sv, "text/x-smarty"sv }, // Latte
        ExtensionRule{ ".less"sv, "text/x-less"sv }, // LESS source code
        ExtensionRule{ ".lfe"sv, "text/x-common-lisp"sv }, // LFE
        ExtensionRule{ ".lha"sv, "application/x-lzh-compressed"sv }, // LHA
        ExtensionRule{ ".lhs"sv, "text/x-literate-haskell"sv }, // Literate Haskell
        ExtensionRule{ ".lisp"sv, "text/x-common-lisp"sv }, // Common Lisp
        ExtensionRule{ ".log"sv, "text/x-log"sv }, // application log
        ExtensionRule{ ".lookml"sv, "text/x-yaml"sv }, // LookML
        ExtensionRule{ ".ls"sv, "text/x-livescript"sv }, // LiveScript
        ExtensionRule{ ".lua"sv, "text/x-lua"sv }, // Lua source code
        ExtensionRule{ ".lvproj"sv, "text/xml"sv }, // LabVIEW
        ExtensionRule{ ".lwp"sv, "application/vnd.lotus-wordpro"sv }, // Lotus Word Pro
        ExtensionRule{ ".lz"sv, "application/x-lzip"sv }, // Lzip
        ExtensionRule{ ".lzma"sv, "application/x-lzma"sv }, // LZMA Alone
        ExtensionRule{ ".m"sv, "text/x-objcsrc"sv }, // Objective-C source code
        ExtensionRule{ ".m3"sv, "text/x-modula"sv }, // Modula source code
        ExtensionRule{ ".m3u"sv, "audio/x-mpegurl"sv }, // MP3 Playlist File
        ExtensionRule{ ".maff"sv, "application/x-maff"sv }, // MAFF
        ExtensionRule{ ".mak"sv, "text/x-cmake"sv }, // Makefile
        ExtensionRule{ ".marko"sv, "text/html"sv }, // Marko
        ExtensionRule{ ".mas"sv, "application/vnd.lotus-freelance"sv }, // Lotus Freelance Smartmaster Graphics
        ExtensionRule{ ".mat"sv, "application/matlab-mat"sv }, // MAT-File Level 5 File Format
        ExtensionRule{ ".mathematica"sv, "text/x-mathematica"sv }, // Mathematica
        ExtensionRule{ ".matlab"sv, "text/x-octave"sv }, // MATLAB
        ExtensionRule{ ".maxpat"sv, "application/json"sv }, // Max
        ExtensionRule{ ".mbox"sv, "application/mbox"sv }, // MBOX Email Format
        ExtensionRule{ ".mbx"sv, "application/mbox"sv }, // Mbox
        ExtensionRule{ ".md"sv, "text/markdown"sv }, // Markdown
        ExtensionRule{ ".mdi"sv, "image/vnd.ms-modi"sv }, // Microsoft Document Imaging
        ExtensionRule{ ".mef"sv, "image/x-raw-mamiya"sv }, // Mamiya raw image
        ExtensionRule{ ".metal"sv, "text/x-c++src"sv }, // Metal
        ExtensionRule{ ".mht"sv, "multipart/related"sv }, // Microsoft Web Archive
        ExtensionRule{ ".mid"sv, "audio/midi"sv }, // Musical Instrument Digital Interface
        ExtensionRule{ ".mif"sv, "application/x-mif"sv }, // FrameMaker Interchange Format
        ExtensionRule{ ".mix"sv, "image/vnd.mix"sv }, // MIX (PhotoDraw)
        ExtensionRule{ ".mj2"sv, "video/mj2"sv }, // MJ2 (Motion JPEG 2000)
        ExtensionRule{ ".mkv"sv, "video/x-matroska"sv }, // Matroska Multimedia Container
        ExtensionRule{ ".ml"sv, "text/x-ocaml"sv }, // OCaml
        ExtensionRule{ ".mlp"sv, "audio/vnd.dolby.mlp"sv }, // Dolby MLP Lossless Audio
        ExtensionRule{ ".mm"sv, "application/x-freemind"sv }, // Mm
        ExtensionRule{ ".mmp"sv, "application/vnd.mindjet.mindmanager"sv }, // MindManager
        ExtensionRule{ ".mmr"sv, "image/vnd.fujixerox.edmics-mmr"sv }, // Xerox EDMICS-MMR
        ExtensionRule{ ".mng"sv, "video/x-mng"sv }, // Multiple-image Network Graphics
        ExtensionRule{ ".mo"sv, "text/x-modelica"sv }, // Modelica
        ExtensionRule{ ".mobi"sv, "application/x-mobipocket-ebook"sv }, // Mobipocket File Format
        ExtensionRule{ ".mol"sv, "chemical/x-mdl-molfile"sv }, // MOL
        ExtensionRule{ ".mos"sv, "image/x-raw-leaf"sv }, // Leaf raw image
        ExtensionRule{ ".mov"sv, "video/quicktime"sv }, // QuickTime File Format
        ExtensionRule{ ".mp1"sv, "audio/mpeg"sv }, // MPEG Audio Layer I
        ExtensionRule{ ".mp2"sv, "audio/mpeg"sv }, // MPEG Audio Stream, Layer II
        ExtensionRule{ ".mp3"sv, "audio/mpeg"sv }, // MP3 File Format
        ExtensionRule{ ".mp4"sv, "video/mp4"sv }, // MPEG-4 File Format, Version 2
        ExtensionRule{ ".mpeg"sv, "video/mpeg"sv }, // MPEG Movie Clip
        ExtensionRule{ ".mpg"sv, "video/mpeg"sv }, // MPEG-1
        ExtensionRule{ ".mpga"sv, "audio/mpeg"sv }, // MPEG-1 Audio Layer 3
        ExtensionRule{ ".mrc"sv, "application/marc"sv }, // MARC
        ExtensionRule{ ".mrw"sv, "image/x-raw-minolta"sv }, // Minolta raw image
        ExtensionRule{ ".msg"sv, "application/vnd.ms-outlook"sv }, // Microsoft Outlook Message
        ExtensionRule{ ".msi"sv, "application/x-msi"sv }, // Microsoft Windows Installer
        ExtensionRule{ ".mso"sv, "application/x-mso"sv }, // ActiveMime
        ExtensionRule{ ".mtml"sv, "text/html"sv }, // MTML
        ExtensionRule{ ".muf"sv, "text/x-forth"sv }, // MUF
        ExtensionRule{ ".mumps"sv, "text/x-mumps"sv }, // M
        ExtensionRule{ ".mxf"sv, "application/mxf"sv }, // Material Exchange Format (MXF)
        ExtensionRule{ ".mxl"sv, "application/vnd.recordare.musicxml"sv }, // Compressed Music XML
        ExtensionRule{ ".mxmf"sv, "audio/mobile-xmf"sv }, // Mobile eXtensible Music Format
        ExtensionRule{ ".n3"sv, "text/n3"sv }, // Notation3
        ExtensionRule{ ".nap"sv, "image/naplps"sv }, // NAPLPS
        ExtensionRule{ ".nb"sv, "application/mathematica"sv }, // Mathematica Notebook
        ExtensionRule{ ".nc"sv, "application/x-netcdf"sv }, // NetCDF-3 (Network Common Data Form, version 3)
        ExtensionRule{ ".nef"sv, "image/x-raw-nikon"sv }, // Nikon raw image
        ExtensionRule{ ".nfo"sv, "text/x-nfo"sv }, // NFO
        ExtensionRule{ ".nginxconf"sv, "text/x-nginx-conf"sv }, // Nginx
        ExtensionRule{ ".nif"sv, "application/vnd.music-niff"sv }, // Notation Interchange File Format
        ExtensionRule{ ".nl"sv, "text/x-common-lisp"sv }, // NewLisp
        ExtensionRule{ ".nlogo"sv, "text/x-common-lisp"sv }, // NetLogo
        ExtensionRule{ ".nsf"sv, "application/vnd.lotus-notes"sv }, // Notes Storage Facility
        ExtensionRule{ ".nsi"sv, "text/x-nsis"sv }, // NSIS
        ExtensionRule{ ".ntf"sv, "application/vnd.nitf"sv }, // National Imagery Transmission Format
        ExtensionRule{ ".nu"sv, "text/x-scheme"sv }, // Nu
        ExtensionRule{ ".numpy"sv, "text/x-python"sv }, // NumPy
        ExtensionRule{ ".nut"sv, "text/x-c++src"sv }, // Squirrel
        ExtensionRule{ ".ocaml"sv, "text/x-ocaml"sv }, // Ocaml source code
        ExtensionRule{ ".odb"sv, "application/vnd.oasis.opendocument.database"sv }, // OpenDocument Database Front End Document Format (ODB), Version 1.2,  ISO 26300-1:2015
        ExtensionRule{ ".odc"sv, "application/vnd.oasis.opendocument.chart"sv }, // OpenDocument v1.0: Chart document
        ExtensionRule{ ".odf"sv, "application/vnd.oasis.opendocument.formula"sv }, // OpenDocument v1.0: Formula document
        ExtensionRule{ ".odft"sv, "application/vnd.oasis.opendocument.formula-template"sv }, // OpenDocument v1.0: Formula document used as template
        ExtensionRule{ ".odg"sv, "application/vnd.oasis.opendocument.graphics"sv }, // OpenDocument Drawing
        ExtensionRule{ ".odi"sv, "application/vnd.oasis.opendocument.image"sv }, // OpenDocument v1.0: Image document
        ExtensionRule{ ".odm"sv, "application/vnd.oasis.opendocument.text-master"sv }, // OpenDocument
        ExtensionRule{ ".odp"sv, "application/vnd.oasis.opendocument.presentation"sv }, // OpenDocument Presentation
        ExtensionRule{ ".ods"sv, "application/vnd.oasis.opendocument.spreadsheet"sv }, // OpenDocument Spreadsheet
        ExtensionRule{ ".odt"sv, "application/vnd.oasis.opendocument.text"sv }, // OpenDocument Text
        ExtensionRule{ ".oga"sv, "audio/ogg"sv }, // Ogg Vorbis Audio
        ExtensionRule{ ".ogg"sv, "audio/ogg"sv }, // Ogg Vorbis Codec Compressed Multimedia File
        ExtensionRule{ ".ogm"sv, "video/x-ogm"sv }, // Ogg Packaged OGM Video
        ExtensionRule{ ".ogv"sv, "video/ogg"sv }, // Ogg Vorbis Video
        ExtensionRule{ ".ogx"sv, "application/ogg"sv }, // Ogg Skeleton
        ExtensionRule{ ".one"sv, "application/msonenote"sv }, // Microsoft OneNote
        ExtensionRule{ ".opf"sv, "application/x-dtbook+xml"sv }, // DTB (Digital Talking Book), 2005
        ExtensionRule{ ".opus"sv, "audio/opus"sv }, // Ogg Opus Codec Compressed WAV File
        ExtensionRule{ ".ora"sv, "image/openraster"sv }, // OpenRaster
        ExtensionRule{ ".orf"sv, "image/x-raw-olympus"sv }, // Olympus raw image
        ExtensionRule{ ".otc"sv, "application/vnd.oasis.opendocument.chart-template"sv }, // OpenDocument v1.0: Chart document used as template
        ExtensionRule{ ".otf"sv, "application/x-font-otf"sv }, // OpenType Font
        ExtensionRule{ ".otg"sv, "application/vnd.oasis.opendocument.graphics-template"sv }, // OpenDocument v1.0: Graphics document used as template
        ExtensionRule{ ".oth"sv, "application/vnd.oasis.opendocument.text-web"sv }, // OpenDocument v1.0: Text document used as template for HTML documents
        ExtensionRule{ ".oti"sv, "application/vnd.oasis.opendocument.image-template"sv }, // OpenDocument v1.0: Image document used as template
        ExtensionRule{ ".otm"sv, "application/vnd.oasis.opendocument.text-master"sv }, // OpenDocument v1.0: Global Text document
        ExtensionRule{ ".otp"sv, "application/vnd.oasis.opendocument.presentation-template"sv }, // OpenDocument v1.0: Presentation document used as template
        ExtensionRule{ ".ots"sv, "application/vnd.oasis.opendocument.spreadsheet-template"sv }, // OpenDocument v1.0: Spreadsheet document used as template
        ExtensionRule{ ".ott"sv, "application/vnd.oasis.opendocument.text-template"sv }, // OpenDocument v1.0: Text document used as template
        ExtensionRule{ ".oxps"sv, "application/oxps"sv }, // OpenXPS
        ExtensionRule{ ".oz"sv, "text/x-oz"sv }, // Oz
        ExtensionRule{ ".p"sv, "text/x-pascal"sv }, // Pascal source code
        ExtensionRule{ ".p65"sv, "application/vnd.pagemaker"sv }, // Pagemaker Document (Generic)
        ExtensionRule{ ".pab"sv, "application/vnd.ms-outlook"sv }, // Personal Folder File
        ExtensionRule{ ".pack"sv, "application/package"sv }, // Package (Web)
        ExtensionRule{ ".pam"sv, "image/x-portable-arbitrarymap"sv }, // Portable Arbitrary Map
        ExtensionRule{ ".pas"sv, "text/x-pascal"sv }, // Pascal
        ExtensionRule{ ".pbm"sv, "image/x-portable-bitmap"sv }, // Netpbm formats
        ExtensionRule{ ".pcap"sv, "application/vnd.tcpdump.pcap"sv }, // TCPDump pcap packet capture
        ExtensionRule{ ".pcapng"sv, "application/vnd.tcpdump.pcap"sv }, // pcap Next Generation Packet Capture
        ExtensionRule{ ".pcl"sv, "application/vnd.hp-pcl"sv }, // PCL
        ExtensionRule{ ".pcx"sv, "image/vnd.zbrush.pcx"sv }, // PCX
        ExtensionRule{ ".pdb"sv, "application/vnd.palm"sv }, // Palm OS Database
        ExtensionRule{ ".pdf"sv, "application/pdf"sv }, // Portable Document Format
        ExtensionRule{ ".pfm"sv, "application/x-font-printer-metric"sv }, // Printer Font Metric
        ExtensionRule{ ".pfr"sv, "application/font-tdpfr"sv }, // PFR
        ExtensionRule{ ".pgm"sv, "image/x-portable-graymap"sv }, // Portable Graymap Graphic
        ExtensionRule{ ".pgn"sv, "application/x-chess-pgn"sv }, // PGN
        ExtensionRule{ ".pgsql"sv, "text/x-sql"sv }, // PLpgSQL
        ExtensionRule{ ".php"sv, "text/x-php"sv }, // PHP script
        ExtensionRule{ ".phtml"sv, "application/x-httpd-php"sv }, // HTML+PHP
        ExtensionRule{ ".pic"sv, "image/x-pict"sv }, // Apple Macintosh QuickDraw/PICT Format
        ExtensionRule{ ".pict"sv, "image/x-pict"sv }, // PICT
        ExtensionRule{ ".pkpass"sv, "application/vnd.apple.pkpass"sv }, // PKPass
        ExtensionRule{ ".pl"sv, "text/x-perl"sv }, // Perl script
        ExtensionRule{ ".pls"sv, "text/x-plsql"sv }, // PLSQL
        ExtensionRule{ ".png"sv, "image/png"sv }, // Portable Network Graphics
        ExtensionRule{ ".pnm"sv, "image/x-portable-anymap"sv }, // Portable Any Map
        ExtensionRule{ ".pod"sv, "text/x-perl"sv }, // Pod
        ExtensionRule{ ".por"sv, "application/x-spss-por"sv }, // SPSS Portable File, ASCII encoding
        ExtensionRule{ ".potx"sv, "application/vnd.openxmlformats-officedocument.presentationml.template"sv }, // Office Open XML Presentation Template
        ExtensionRule{ ".pp"sv, "text/x-puppet"sv }, // Puppet
        ExtensionRule{ ".ppam"sv, "application/vnd.ms-powerpoint.addin.macroenabled.12"sv }, // Office Open XML Presentation Add-in (macro-enabled)
        ExtensionRule{ ".ppm"sv, "image/x-portable-pixmap"sv }, // Portable Pixel Map - ASCII
        ExtensionRule{ ".ppsm"sv, "application/vnd.ms-powerpoint.slideshow.macroenabled.12"sv }, // Office Open XML Presentation Slideshow (macro-enabled)
        ExtensionRule{ ".ppsx"sv, "application/vnd.openxmlformats-officedocument.presentationml.slideshow"sv }, // Office Open XML Presentation Slideshow
        ExtensionRule{ ".ppt"sv, "application/vnd.ms-powerpoint"sv }, // Microsoft Powerpoint Presentation
        ExtensionRule{ ".pptm"sv, "application/vnd.ms-powerpoint.presentation.macroenabled.12"sv }, // Office Open XML Presentation (macro-enabled)
        ExtensionRule{ ".pptx"sv, "application/vnd.openxmlformats-officedocument.presentationml.presentation"sv }, // Office Open XML Presentation
        ExtensionRule{ ".prc"sv, "application/vnd.palm"sv }, // PRC (Palm OS)
        ExtensionRule{ ".pro"sv, "text/x-prolog"sv }, // Prolog source code
        ExtensionRule{ ".properties"sv, "text/properties"sv }, // Java Properties
        ExtensionRule{ ".proto"sv, "text/x-protobuf"sv }, // Protocol Buffer
        ExtensionRule{ ".ps"sv, "application/postscript"sv }, // PostScript
        ExtensionRule{ ".ps1"sv, "application/x-powershell"sv }, // PowerShell
        ExtensionRule{ ".psb"sv, "image/vnd.adobe.photoshop"sv }, // Adobe Photoshop Large Document Format
        ExtensionRule{ ".psd"sv, "image/vnd.adobe.photoshop"sv }, // Adobe Photoshop
        ExtensionRule{ ".pst"sv, "application/vnd.ms-outlook-pst"sv }, // Outlook Personal Folders File Format
        ExtensionRule{ ".ptx"sv, "image/x-raw-pentax"sv }, // Pentax raw image
        ExtensionRule{ ".purs"sv, "text/x-haskell"sv }, // PureScript
        ExtensionRule{ ".pxn"sv, "image/x-raw-logitech"sv }, // Logitech raw image
        ExtensionRule{ ".py"sv, "text/x-python"sv }, // Python script
        ExtensionRule{ ".pyx"sv, "text/x-cython"sv }, // Cython
        ExtensionRule{ ".qcd"sv, "application/vnd.quark.quarkxpress"sv }, // Quark Xpress Data File
        ExtensionRule{ ".qcp"sv, "audio/qcelp"sv }, // QCP Audio File Format
        ExtensionRule{ ".qif"sv, "application/qif"sv }, // Quicken Interchange Format
        ExtensionRule{ ".qxp"sv, "application/vnd.quark.quarkxpress"sv }, // QuarkXPress
        ExtensionRule{ ".qxp report"sv, "application/vnd.quark.quarkxpress"sv }, // Quark Xpress Report File
        ExtensionRule{ ".r"sv, "text/x-rsrc"sv }, // R source code
        ExtensionRule{ ".r3d"sv, "image/x-raw-red"sv }, // Red raw image
        ExtensionRule{ ".ra"sv, "audio/vnd.rn-realaudio"sv }, // RealAudio
        ExtensionRule{ ".raf"sv, "image/x-raw-fuji"sv }, // Fuji raw image
        ExtensionRule{ ".ram"sv, "audio/vnd.rn-realaudio"sv }, // RealAudio Metafile
        ExtensionRule{ ".raml"sv, "text/x-yaml"sv }, // RAML
        ExtensionRule{ ".rar"sv, "application/vnd.rar"sv }, // RAR
        ExtensionRule{ ".rar "sv, "application/vnd.rar"sv }, // RAR Archive File Format Family
        ExtensionRule{ ".ras"sv, "image/x-sun-raster"sv }, // Sun Raster Image
        ExtensionRule{ ".raw"sv, "image/x-raw-panasonic"sv }, // Panasonic raw image
        ExtensionRule{ ".rb"sv, "text/x-ruby"sv }, // Ruby source code
        ExtensionRule{ ".rdf"sv, "application/rdf+xml"sv }, // RDF
        ExtensionRule{ ".re"sv, "text/x-rustsrc"sv }, // Reason
        ExtensionRule{ ".reg"sv, "text/x-properties"sv }, // Windows Registry Entries
        ExtensionRule{ ".rest"sv, "text/x-rst"sv }, // reStructuredText source code
        ExtensionRule{ ".rexx"sv, "text/x-rexx"sv }, // Rexx source code
        ExtensionRule{ ".rfa"sv, "application/octet-stream"sv }, // Revit Family File
        ExtensionRule{ ".rft"sv, "application/octet-stream"sv }, // Revit Family Template
        ExtensionRule{ ".rg"sv, "text/x-clojure"sv }, // Rouge
        ExtensionRule{ ".rgb"sv, "image/x-rgb"sv }, // Silicon Graphics RGB Bitmap
        ExtensionRule{ ".rhtml"sv, "application/x-erb"sv }, // RHTML
        ExtensionRule{ ".rlc"sv, "image/vnd.fujixerox.edmics-rlc"sv }, // Xerox EDMICS-RLC
        ExtensionRule{ ".rm"sv, "application/vnd.rn-realmedia"sv }, // RealAudio, Version 10
        ExtensionRule{ ".rmd"sv, "text/x-gfm"sv }, // RMarkdown
        ExtensionRule{ ".rmi"sv, "audio/mid"sv }, // RIFF-based MIDI File Format
        ExtensionRule{ ".rmp"sv, "audio/x-pn-realaudio-plugin"sv }, // RealMedia Player Plug-in
        ExtensionRule{ ".roff"sv, "text/troff"sv }, // Roff
        ExtensionRule{ ".rpm"sv, "application/x-rpm"sv }, // RedHat Package Manager
        ExtensionRule{ ".rs"sv, "text/x-rustsrc"sv }, // Rust
        ExtensionRule{ ".rss"sv, "application/rss+xml"sv }, // RSS
        ExtensionRule{ ".rst"sv, "text/x-rst"sv }, // reStructuredText
        ExtensionRule{ ".rte"sv, "application/octet-stream"sv }, // Revit Template
        ExtensionRule{ ".rtf"sv, "application/rtf"sv }, // Rich Text Format File
        ExtensionRule{ ".rv"sv, "video/vnd.rn-realvideo"sv }, // Real Video
        ExtensionRule{ ".rvg"sv, "application/octet-stream"sv }, // Revit External Group
        ExtensionRule{ ".rvt"sv, "application/octet-stream"sv }, // Revit Project
        ExtensionRule{ ".rws"sv, "application/octet-stream"sv }, // Revit Workspace
        ExtensionRule{ ".rwz"sv, "image/x-raw-rawzor"sv }, // Rawzor raw image
        ExtensionRule{ ".s"sv, "text/x-asm"sv }, // Assembler source code
        ExtensionRule{ ".s7m"sv, "application/x-sas-dmdb"sv }, // SAS DMDB Data Mining Database File
        ExtensionRule{ ".sa7"sv, "application/x-sas-access"sv }, // SAS Access Descriptor
        ExtensionRule{ ".sage"sv, "text/x-python"sv }, // Sage
        ExtensionRule{ ".sam"sv, "application/vnd.lotus-wordpro"sv }, // AMI Professional Document
        ExtensionRule{ ".sas"sv, "application/x-sas"sv }, // SAS Program
        ExtensionRule{ ".sas7bbak"sv, "application/x-sas-backup"sv }, // SAS Backup
        ExtensionRule{ ".sass"sv, "text/x-sass"sv }, // Sass
        ExtensionRule{ ".sav"sv, "application/x-spss-sav"sv }, // SPSS System Data File Format Family (.sav)
        ExtensionRule{ ".sc7"sv, "application/x-sas-catalog"sv }, // SAS Catalog
        ExtensionRule{ ".scala"sv, "text/x-scala"sv }, // Scala source code
        ExtensionRule{ ".sch"sv, "text/xml"sv }, // Eagle
        ExtensionRule{ ".scm"sv, "text/x-scheme"sv }, // Scheme source code
        ExtensionRule{ ".scores"sv, "text/plain"sv }, // Xbill.scores
        ExtensionRule{ ".scss"sv, "text/x-scss"sv }, // SCSS
        ExtensionRule{ ".sd7"sv, "application/x-sas-data"sv }, // SAS Data Set
        ExtensionRule{ ".sda"sv, "application/vnd.stardivision.draw"sv }, // SDA (StarOffice)
        ExtensionRule{ ".sdc"sv, "application/vnd.stardivision.calc"sv }, // SDC
        ExtensionRule{ ".sdn"sv, "text/plain"sv }, // Steel Detailing Neutral Format
        ExtensionRule{ ".sdw"sv, "application/vnd.stardivision.writer"sv }, // StarOffice binary formats
        ExtensionRule{ ".sed"sv, "text/x-sed"sv }, // Sed code
        ExtensionRule{ ".sf7"sv, "application/x-sas-fdb"sv }, // SAS FDB Consolidation Database File
        ExtensionRule{ ".sfd"sv, "application/vnd.font-fontforge-sfd"sv }, // Spline Font Database
        ExtensionRule{ ".sgm"sv, "text/sgml"sv }, // Standard Generalized Markup Language
        ExtensionRule{ ".sgml"sv, "text/sgml"sv }, // SGML
        ExtensionRule{ ".sh"sv, "application/x-sh"sv }, // UNIX/LINUX Shell Script
        ExtensionRule{ ".sh-session"sv, "text/x-sh"sv }, // ShellSession
        ExtensionRule{ ".shar"sv, "application/x-shar"sv }, // Shell Archive Format
        ExtensionRule{ ".shtml"sv, "text/x-server-parsed-html"sv }, // Server Side Includes
        ExtensionRule{ ".si7"sv, "application/x-sas-data-index"sv }, // SAS Data Set Index
        ExtensionRule{ ".sid"sv, "audio/prs.sid"sv }, // SID
        ExtensionRule{ ".sit"sv, "application/x-stuffit"sv }, // StuffIt
        ExtensionRule{ ".sitx"sv, "application/x-stuffitx"sv }, // StuffIt X
        ExtensionRule{ ".skb"sv, "application/octet-stream"sv }, // SketchUp Document
        ExtensionRule{ ".skp"sv, "application/vnd.koan"sv }, // SSEYO Koan File
        ExtensionRule{ ".sla"sv, "application/vnd.scribus"sv }, // Scribus
        ExtensionRule{ ".sld"sv, "application/sld"sv }, // AutoCAD Slide
        ExtensionRule{ ".sldprt"sv, "application/sldworks"sv }, // SolidWorks CAD program
        ExtensionRule{ ".slim"sv, "text/x-slim"sv }, // Slim
        ExtensionRule{ ".sls"sv, "text/x-yaml"sv }, // SaltStack
        ExtensionRule{ ".sm7"sv, "application/x-sas-mddb"sv }, // SAS MDDB Multi-Dimensional Database File
        ExtensionRule{ ".smi"sv, "application/smil+xml"sv }, // SMIL Multimedia
        ExtensionRule{ ".smk"sv, "video/vnd.radgamettools.smacker"sv }, // Smacker
        ExtensionRule{ ".soy"sv, "text/x-soy"sv }, // Closure Templates
        ExtensionRule{ ".sp7"sv, "application/x-sas-putility"sv }, // SAS Permanent Utility
        ExtensionRule{ ".sparql"sv, "application/sparql-query"sv }, // SPARQL
        ExtensionRule{ ".spec"sv, "text/x-rpm-spec"sv }, // RPM Spec
        ExtensionRule{ ".spl"sv, "application/x-futuresplash"sv }, // Macromedia FutureSplash File
        ExtensionRule{ ".spx"sv, "audio/speex"sv }, // Ogg Speex Audio Format
        ExtensionRule{ ".sql"sv, "text/x-sql"sv }, // SQL code
        ExtensionRule{ ".sr7"sv, "application/x-sas-itemstor"sv }, // SAS Item Store (ItemStor) File
        ExtensionRule{ ".srl"sv, "application/sereal"sv }, // Sereal binary serialization format
        ExtensionRule{ ".srt"sv, "text/x-common-lisp"sv }, // SRecode Template
        ExtensionRule{ ".ss7"sv, "application/x-sas-program-data"sv }, // SAS Stored Program (DATA Step)
        ExtensionRule{ ".ssml"sv, "application/ssml+xml"sv }, // Speech Synthesis Markup Language
        ExtensionRule{ ".st"sv, "text/x-stsrc"sv }, // Smalltalk source code
        ExtensionRule{ ".st7"sv, "application/x-sas-audit"sv }, // SAS Audit
        ExtensionRule{ ".stw"sv, "application/vnd.sun.xml.writer.template"sv }, // STW
        ExtensionRule{ ".stx"sv, "application/x-sas-transport"sv }, // SAS Transport File
        ExtensionRule{ ".su7"sv, "application/x-sas-utility"sv }, // SAS Utility
        ExtensionRule{ ".sublime-build"sv, "text/javascript"sv }, // JSON with Comments
        ExtensionRule{ ".sv"sv, "text/x-systemverilog"sv }, // SystemVerilog
        ExtensionRule{ ".sv7"sv, "application/x-sas-view"sv }, // SAS Data Set View
        ExtensionRule{ ".svf"sv, "image/vnd.svf"sv }, // Simple Vector Format
        ExtensionRule{ ".svg"sv, "image/svg+xml"sv }, // Scalable Vector Graphics
        ExtensionRule{ ".svgz"sv, "image/svg+xml"sv }, // Scalable Vector Graphics Compressed
        ExtensionRule{ ".swf"sv, "application/vnd.adobe.flash-movie"sv }, // SWF
        ExtensionRule{ ".swift"sv, "text/x-swift"sv }, // Swift
        ExtensionRule{ ".sxd"sv, "application/vnd.sun.xml.draw"sv }, // SXD
        ExtensionRule{ ".sxi"sv, "application/vnd.sun.xml.impress"sv }, // SXI
        ExtensionRule{ ".sxw"sv, "application/vnd.sun.xml.writer"sv }, // OpenOffice.org XML
        ExtensionRule{ ".sz"sv, "application/x-snappy-framed"sv }, // Snappy Framed
        ExtensionRule{ ".t"sv, "application/x-tads"sv }, // TADS
        ExtensionRule{ ".tap"sv, "image/vnd.tencent.tap"sv }, // TAP (Tencent)
        ExtensionRule{ ".tar"sv, "application/x-tar"sv }, // Tape Archive
        ExtensionRule{ ".tcl"sv, "text/x-tcl"sv }, // Tcl
        ExtensionRule{ ".tcsh"sv, "text/x-sh"sv }, // Tcsh
        ExtensionRule{ ".tex"sv, "text/x-tex"sv }, // TeX Source
        ExtensionRule{ ".textile"sv, "text/x-textile"sv }, // Textile
        ExtensionRule{ ".tfw"sv, "text/plain"sv }, // ESRI World File
        ExtensionRule{ ".tfx"sv, "image/tiff"sv }, // Tagged Image File Format for Internet Fax (TIFF-FX)
        ExtensionRule{ ".thmx"sv, "application/vnd.ms-officetheme"sv }, // Microsoft Office Theme
        ExtensionRule{ ".tif"sv, "image/tiff"sv }, // Tagged Image File Format for Image Technology (TIFF/IT)
        ExtensionRule{ ".tif "sv, "image/tiff"sv }, // Digital Raster Graphic as TIFF
        ExtensionRule{ ".tiff"sv, "image/tiff"sv }, // Tagged Image File Format
        ExtensionRule{ ".toml"sv, "text/x-toml"sv }, // TOML
        ExtensionRule{ ".torrent"sv, "application/x-bittorrent"sv }, // Torrent file
        ExtensionRule{ ".tpl"sv, "text/x-smarty"sv }, // Smarty
        ExtensionRule{ ".ts"sv, "application/typescript"sv }, // TypeScript
        ExtensionRule{ ".tsv"sv, "text/tab-separated-values"sv }, // Tab-separated values
        ExtensionRule{ ".ttf"sv, "application/x-font-ttf"sv }, // TrueType Font
        ExtensionRule{ ".ttl"sv, "text/turtle"sv }, // Turtle
        ExtensionRule{ ".twig"sv, "text/x-twig"sv }, // Twig
        ExtensionRule{ ".txt"sv, "text/plain"sv }, // Plain text
        ExtensionRule{ ".u3d"sv, "model/u3d"sv }, // Universal 3D (U3D) format family. ECMA-363, Editions 1-4
        ExtensionRule{ ".uc"sv, "text/x-java"sv }, // UnrealScript
        ExtensionRule{ ".ulx"sv, "application/x-glulx"sv }, // Glulx
        ExtensionRule{ ".uno"sv, "text/x-csharp"sv }, // Uno
        ExtensionRule{ ".upc"sv, "text/x-csrc"sv }, // Unified Parallel C
        ExtensionRule{ ".url"sv, "application/x-url"sv }, // Internet Shortcut
        ExtensionRule{ ".v"sv, "text/x-verilog"sv }, // Verilog source code
        ExtensionRule{ ".vb"sv, "text/x-vb"sv }, // Visual Basic
        ExtensionRule{ ".vbs"sv, "text/x-vbscript"sv }, // VBScript source code
        ExtensionRule{ ".vcd"sv, "application/x-cdlink"sv }, // Virtual CD-ROM CD Image File
        ExtensionRule{ ".vcf"sv, "text/vcard"sv }, // VCard
        ExtensionRule{ ".vcs"sv, "text/x-vcalendar"sv }, // VCalendar format
        ExtensionRule{ ".vhd"sv, "text/x-vhdl"sv }, // VHDL source code
        ExtensionRule{ ".vhdl"sv, "text/x-vhdl"sv }, // VHDL
        ExtensionRule{ ".viv"sv, "video/vnd-vivo"sv }, // VivoActive
        ExtensionRule{ ".vmdk"sv, "application/x-vmdk"sv }, // Virtual Disk Format
        ExtensionRule{ ".vmt"sv, "application/vnd.valve.source.material"sv }, // Valve Material Type
        ExtensionRule{ ".volt"sv, "text/x-d"sv }, // Volt
        ExtensionRule{ ".vot"sv, "application/x-votable+xml"sv }, // VOTable
        ExtensionRule{ ".vpb"sv, "image/vpb"sv }, // Quantel VPB image
        ExtensionRule{ ".vsd"sv, "application/vnd.visio"sv }, // Microsoft Visio Diagram
        ExtensionRule{ ".vsdm"sv, "application/vnd.ms-visio.drawing.macroenabled.12"sv }, // Office Open XML Visio Drawing (macro-enabled)
        ExtensionRule{ ".vsdx"sv, "application/vnd.visio"sv }, // Visio VSDX Drawing File Format
        ExtensionRule{ ".vssm"sv, "application/vnd.ms-visio.stencil.macroenabled.12"sv }, // Office Open XML Visio Stencil (macro-enabled)
        ExtensionRule{ ".vssx"sv, "application/vnd.ms-visio.stencil"sv }, // Office Open XML Visio Stencil (macro-free)
        ExtensionRule{ ".vstm"sv, "application/vnd.ms-visio.template.macroenabled.12"sv }, // Office Open XML Visio Template (macro-enabled)
        ExtensionRule{ ".vstx"sv, "application/vnd.ms-visio.template"sv }, // Office Open XML Visio Template (macro-free)
        ExtensionRule{ ".vtf"sv, "image/vnd.valve.source.texture"sv }, // Valve Texture Format
        ExtensionRule{ ".vtt"sv, "text/vtt"sv }, // Web Video Text Tracks Format
        ExtensionRule{ ".warc"sv, "application/warc"sv }, // WARC, Web ARChive file format
        ExtensionRule{ ".wast"sv, "text/x-common-lisp"sv }, // WebAssembly
        ExtensionRule{ ".wav"sv, "audio/x-wav"sv }, // Waveform Audio
        ExtensionRule{ ".wbmp"sv, "image/vnd.wap.wbmp"sv }, // Wireless Bitmap File Format
        ExtensionRule{ ".webapp"sv, "application/x-web-app-manifest+json"sv }, // Open Web App Manifest
        ExtensionRule{ ".webidl"sv, "text/x-webidl"sv }, // WebIDL
        ExtensionRule{ ".webm"sv, "video/webm"sv }, // WebM
        ExtensionRule{ ".webp"sv, "image/webp"sv }, // WebP
        ExtensionRule{ ".wisp"sv, "text/x-clojure"sv }, // wisp
        ExtensionRule{ ".wks"sv, "application/vnd.lotus-1-2-3"sv }, // Lotus 1-2-3
        ExtensionRule{ ".wma"sv, "audio/x-ms-wma"sv }, // WMA (Windows Media Audio) File Format
        ExtensionRule{ ".wmf"sv, "image/wmf"sv }, // Windows Metafile
        ExtensionRule{ ".wmlc"sv, "application/vnd.wap.wmlc"sv }, // Compiled WML Document
        ExtensionRule{ ".wmls"sv, "text/vnd.wap.wmlscript"sv }, // WML Script
        ExtensionRule{ ".wmlsc"sv, "application/vnd.wap.wmlscriptc"sv }, // Compiled WML Script
        ExtensionRule{ ".wmv"sv, "video/x-ms-wmv"sv }, // WMV (Windows Media Video) File Format
        ExtensionRule{ ".woff"sv, "application/font-woff"sv }, // Web Open Font Format
        ExtensionRule{ ".wpd"sv, "application/vnd.wordperfect"sv }, // WordPerfect
        ExtensionRule{ ".wpl"sv, "application/vnd.ms-wpl"sv }, // Windows Media Playlist
        ExtensionRule{ ".wrl"sv, "model/vrml"sv }, // VRML
        ExtensionRule{ ".wsz"sv, "interface/x-winamp-skin"sv }, // Winamp Skin
        ExtensionRule{ ".x3d"sv, "model/x3d+xml"sv }, // X3D
        ExtensionRule{ ".x3f"sv, "image/x-raw-sigma"sv }, // Sigma raw image
        ExtensionRule{ ".xap"sv, "application/x-silverlight-app"sv }, // Silverlight
        ExtensionRule{ ".xar"sv, "application/vnd.xara"sv }, // Xar (vector graphics)
        ExtensionRule{ ".xbm"sv, "image/x-xbitmap"sv }, // XBM
        ExtensionRule{ ".xc"sv, "text/x-csrc"sv }, // XC
        ExtensionRule{ ".xcf"sv, "image/xcf"sv }, // GIMP Image File
        ExtensionRule{ ".xfdf"sv, "application/vnd.adobe.xfdf"sv }, // XFDF
        ExtensionRule{ ".xhtml"sv, "application/xhtml+xml"sv }, // Extensible HyperText Markup Language (XHTML), 1.0
        ExtensionRule{ ".xif"sv, "image/vnd.xiff"sv }, // XIFF
        ExtensionRule{ ".xlam"sv, "application/vnd.ms-excel.addin.macroenabled.12"sv }, // Office Open XML Workbook Add-in (macro-enabled)
        ExtensionRule{ ".xls"sv, "application/vnd.ms-excel"sv }, // Microsoft Excel Spreadsheet
        ExtensionRule{ ".xlsb"sv, "application/vnd.ms-excel.sheet.binary.macroenabled.12"sv }, // Microsoft Excel 2007 Binary Spreadsheet
        ExtensionRule{ ".xlsm"sv, "application/vnd.ms-excel.sheet.macroenabled.12"sv }, // Office Open XML Workbook (macro-enabled)
        ExtensionRule{ ".xlsx"sv, "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"sv }, // Office Open XML Workbook
        ExtensionRule{ ".xltm"sv, "application/vnd.ms-excel.template.macroenabled.12"sv }, // Office Open XML Workbook Template (macro-enabled)
        ExtensionRule{ ".xltx"sv, "application/vnd.openxmlformats-officedocument.spreadsheetml.template"sv }, // Office Open XML Workbook Template
        ExtensionRule{ ".xm"sv, "audio/xm"sv }, // Extended Module Audio File
        ExtensionRule{ ".xmf"sv, "audio/mobile-xmf"sv }, // XMF, eXtensible Music File Format, Version 1.0
        ExtensionRule{ ".xmind"sv, "application/x-xmind"sv }, // XMind Pro
        ExtensionRule{ ".xml"sv, "application/xml"sv }, // Extensible Markup Language
        ExtensionRule{ ".xmt"sv, "application/mpeg4-iod-xmt"sv }, // MPEG-4, eXtensible MPEG-4 Textual Format (XMT)
        ExtensionRule{ ".xpi"sv, "application/x-xpinstall"sv }, // Cross-Platform Installer Module
        ExtensionRule{ ".xpl"sv, "text/xml"sv }, // XProc
        ExtensionRule{ ".xps"sv, "application/oxps"sv }, // Open XML Paper Specification
        ExtensionRule{ ".xpt"sv, "application/x-sas-xport"sv }, // SAS Transport File Format (XPORT) Family 
        ExtensionRule{ ".xq"sv, "application/xquery"sv }, // XQuery source code
        ExtensionRule{ ".xquery"sv, "application/xquery"sv }, // XQuery
        ExtensionRule{ ".xs"sv, "text/x-csrc"sv }, // XS
        ExtensionRule{ ".xsd"sv, "application/xml"sv }, // XML Schema Definition
        ExtensionRule{ ".xsl"sv, "application/xml"sv }, // Extensible Stylesheet Language
        ExtensionRule{ ".xslfo"sv, "application/xslfo+xml"sv }, // XSL Format
        ExtensionRule{ ".xslt"sv, "application/xslt+xml"sv }, // XSL Transformations
        ExtensionRule{ ".xsp-config"sv, "text/xml"sv }, // XPages
        ExtensionRule{ ".xspf"sv, "application/xspf+xml"sv }, // XML Shareable Playlist Format
        ExtensionRule{ ".xwd"sv, "image/x-xwindowdump"sv }, // X Windows Dump
        ExtensionRule{ ".xz"sv, "application/x-xz"sv }, // XZ
        ExtensionRule{ ".y"sv, "text/x-yacc"sv }, // Yacc/Bison source code
        ExtensionRule{ ".yaml"sv, "text/x-yaml"sv }, // YAML source code
        ExtensionRule{ ".yml"sv, "text/x-yaml"sv }, // YAML
        ExtensionRule{ ".zip"sv, "application/zip"sv }, // Compressed Archive File
    };

    extern const std::span<const ExtensionRule> global_extension_rules_span = global_extension_rules;

} // namespace qadmimes