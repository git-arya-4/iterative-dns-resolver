"""
DNS Wire Format & Codec Subsystem.

Owner: Avidipta
Phase: Phase 2 & 3

Responsibilities:
- RFC 1035 wire encoding and decoding
- Safe byte-level packet parsing
- DNS name encoding and decoding
- DNS header encoding and decoding
- DNS question encoding and decoding
- DNS compression-pointer decoding and generation
- A / AAAA RDATA codecs
- NS / CNAME RDATA codecs
- RDATA codec error handling
"""


# ============================================================
# 2.1 - BYTE CURSOR
# ============================================================

from .cursor import (
    ByteCursor,
    DNSCursorError,
    DNSBoundsError,
)


# ============================================================
# 2.2 - DNS NAME CODEC
# ============================================================

from .name_codec import (
    DNSNameCodec,
    DNSNameCodecError,
    DNSNameEncodeError,
    DNSNameDecodeError,
)


# ============================================================
# 2.3 - DNS HEADER CODEC
# ============================================================

from .header_codec import (
    DNSHeaderCodec,
    DNSHeaderCodecError,
    DNSHeaderEncodeError,
    DNSHeaderDecodeError,
)


# ============================================================
# 2.4 - DNS QUESTION CODEC
# ============================================================

from .question_codec import (
    DNSQuestionCodec,
    DNSQuestionCodecError,
    DNSQuestionEncodeError,
    DNSQuestionDecodeError,
)


# ============================================================
# 3.1 / 3.2 - DNS COMPRESSION
# ============================================================

from .compression import (
    DNSCompressionError,
    DNSCompressionDecodeError,
    DNSCompressionDecoder,
    DNSCompressionEncodeError,
    DNSCompressionEncoder,
)

from .message_decoder import (
    DNSMessageDecoder,
    DNSMessageDecoderError,
    DNSMessageDecodeError,
    DNSUnsupportedRecordTypeError,
)

# ============================================================
# 3.3 / 3.4 - RDATA CODECS
# ============================================================

from .rdata_codec import (
    # Base RDATA errors
    DNSRDataCodecError,
    DNSRDataEncodeError,
    DNSRDataDecodeError,

    # A / AAAA
    DNSAddressRDataCodec,
    DNSAddressRData,

    # NS / CNAME
    DNSNameRDataCodec,
    DNSNSRDataCodec,
    DNSCNameRDataCodec,
    DNSNameRData,
)
from .rdata_codec import (
    DNSRDataCodecError,
    DNSRDataEncodeError,
    DNSRDataDecodeError,

    DNSAddressRDataCodec,
    DNSAddressRData,

    DNSNameRDataCodec,
    DNSNSRDataCodec,
    DNSCNameRDataCodec,
    DNSNameRData,

    DNSMXRDataCodec,
    DNSTXTRDataCodec,
    DNSSOARDataCodec,

    DNSAdvancedRData,
)

from .message_encoder import (
    DNSMessageEncoder,
    DNSMessageEncoderError,
    DNSMessageEncodeError,
    DNSUnsupportedRecordTypeError,
)


# ============================================================
# PUBLIC API
# ============================================================

__all__ = [

    # --------------------------------------------------------
    # 2.1 - Byte Cursor
    # --------------------------------------------------------

    "ByteCursor",
    "DNSCursorError",
    "DNSBoundsError",


    # --------------------------------------------------------
    # 2.2 - DNS Name Codec
    # --------------------------------------------------------

    "DNSNameCodec",
    "DNSNameCodecError",
    "DNSNameEncodeError",
    "DNSNameDecodeError",


    # --------------------------------------------------------
    # 2.3 - DNS Header Codec
    # --------------------------------------------------------

    "DNSHeaderCodec",
    "DNSHeaderCodecError",
    "DNSHeaderEncodeError",
    "DNSHeaderDecodeError",


    # --------------------------------------------------------
    # 2.4 - DNS Question Codec
    # --------------------------------------------------------

    "DNSQuestionCodec",
    "DNSQuestionCodecError",
    "DNSQuestionEncodeError",
    "DNSQuestionDecodeError",


    # --------------------------------------------------------
    # 3.1 / 3.2 - DNS Compression
    # --------------------------------------------------------

    "DNSCompressionError",
    "DNSCompressionDecodeError",
    "DNSCompressionDecoder",
    "DNSCompressionEncodeError",
    "DNSCompressionEncoder",


    # --------------------------------------------------------
    # 3.3 / 3.4 - RDATA
    # --------------------------------------------------------

    "DNSRDataCodecError",
    "DNSRDataEncodeError",
    "DNSRDataDecodeError",

    "DNSAddressRDataCodec",
    "DNSAddressRData",

    "DNSNameRDataCodec",
    "DNSNSRDataCodec",
    "DNSCNameRDataCodec",
    "DNSNameRData",

    # --------------------------------------------------------
    # 3.5 - MX / TXT / SOA RDATA
    # --------------------------------------------------------

    "DNSMXRDataCodec",
    "DNSTXTRDataCodec",
    "DNSSOARDataCodec",
    "DNSAdvancedRData",

    "DNSMessageDecoder",
    "DNSMessageDecoderError",
    "DNSMessageDecodeError",
    "DNSUnsupportedRecordTypeError",

    "DNSMessageEncoder",
    "DNSMessageEncoderError",
    "DNSMessageEncodeError",
    "DNSUnsupportedRecordTypeError",
]