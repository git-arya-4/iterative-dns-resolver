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
- Name compression pointer parsing and generation
- RDATA codecs across required DNS record types
- Implementation of DNSCodecProtocol contract
"""

# ============================================================
# 2.1 SAFE BYTE CURSOR
# ============================================================

from .cursor import (
    ByteCursor,
    DNSCursorError,
    DNSBoundsError,
)


# ============================================================
# 2.2 DNS NAME CODEC
# ============================================================

from .name_codec import (
    DNSNameCodec,
    DNSNameCodecError,
    DNSNameEncodeError,
    DNSNameDecodeError,
)


# ============================================================
# 2.3 DNS HEADER CODEC
# ============================================================

from .header_codec import (
    DNSHeaderCodec,
    DNSHeaderCodecError,
    DNSHeaderEncodeError,
    DNSHeaderDecodeError,
)


# ============================================================
# 2.4 DNS QUESTION CODEC
# ============================================================

from .question_codec import (
    DNSQuestionCodec,
    DNSQuestionCodecError,
    DNSQuestionEncodeError,
    DNSQuestionDecodeError,
)


# ============================================================
# PUBLIC API
# ============================================================

__all__ = [
    # 2.1 Byte Cursor
    "ByteCursor",
    "DNSCursorError",
    "DNSBoundsError",

    # 2.2 DNS Name Codec
    "DNSNameCodec",
    "DNSNameCodecError",
    "DNSNameEncodeError",
    "DNSNameDecodeError",

    # 2.3 DNS Header Codec
    "DNSHeaderCodec",
    "DNSHeaderCodecError",
    "DNSHeaderEncodeError",
    "DNSHeaderDecodeError",

    # 2.4 DNS Question Codec
    "DNSQuestionCodec",
    "DNSQuestionCodecError",
    "DNSQuestionEncodeError",
    "DNSQuestionDecodeError",
]