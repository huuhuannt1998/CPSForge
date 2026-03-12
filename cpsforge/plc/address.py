"""
CPSForge PLC Address Parser
============================
Parses Siemens S7 canonical tag addresses into the snap7 read/write
parameters needed by the python-snap7 library.

Supported address formats:
  DB<n>,<type><byte>         e.g. DB1,REAL4   (data block)
  DB<n>,<type><byte>.<bit>   e.g. DB1,BOOL0.3 (data block bit)
  MW<byte>                   e.g. MW10         (memory word)
  MD<byte>                   e.g. MD12         (memory dword / real)
  MB<byte>                   e.g. MB4          (memory byte)
  M<byte>.<bit>              e.g. M0.5         (memory bit)
  IW<byte>                   e.g. IW0          (input word)
  QW<byte>                   e.g. QW2          (output word)
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import Enum
from typing import Optional


class S7Area(int, Enum):
    """Snap7 area constants (matches snap7.types.Areas)."""
    PE = 0x81   # Process inputs (I)
    PA = 0x82   # Process outputs (Q)
    MK = 0x83   # Merkers / flags (M)
    DB = 0x84   # Data blocks
    CT = 0x1C   # Counters
    TM = 0x1D   # Timers


class S7WordLen(int, Enum):
    """Snap7 word-length constants (matches snap7.types.WordLen)."""
    BIT = 0x01
    BYTE = 0x02
    WORD = 0x04
    DWORD = 0x06
    REAL = 0x08


@dataclass
class S7Address:
    """Decoded snap7 read/write parameters for one tag."""
    area: S7Area
    word_len: S7WordLen
    db_number: int            # 0 if not a DB area
    start: int                # Byte offset
    bit: int                  # Bit position (0-7), only used for BIT word_len
    size: int                 # Number of bytes to read/write


# ---------------------------------------------------------------------------
# Parser
# ---------------------------------------------------------------------------

# DB address: DB1,REAL4 or DB1,BOOL0.3
_RE_DB = re.compile(
    r"^DB(?P<db>\d+),(?P<type>BOOL|BYTE|INT|DINT|WORD|DWORD|REAL)(?P<byte>\d+)(?:\.(?P<bit>\d))?$",
    re.IGNORECASE,
)

# Memory area: MW10, MD12, MB4, or M0.5
_RE_M = re.compile(
    r"^M(?P<subtype>W|D|B)?(?P<byte>\d+)(?:\.(?P<bit>\d))?$",
    re.IGNORECASE,
)

# Input/output words: IW0, QW2
_RE_IQ = re.compile(
    r"^(?P<area>[IQ])(?P<subtype>W|D|B)(?P<byte>\d+)$",
    re.IGNORECASE,
)

_TYPE_TO_WORDLEN: dict[str, tuple[S7WordLen, int]] = {
    # (word_len, byte_size)
    "BOOL":  (S7WordLen.BIT,   1),
    "BYTE":  (S7WordLen.BYTE,  1),
    "INT":   (S7WordLen.WORD,  2),
    "WORD":  (S7WordLen.WORD,  2),
    "DINT":  (S7WordLen.DWORD, 4),
    "DWORD": (S7WordLen.DWORD, 4),
    "REAL":  (S7WordLen.REAL,  4),
}


def parse_address(address: str) -> S7Address:
    """
    Parse a CPSForge tag address string into an :class:`S7Address`.

    Raises
    ------
    ValueError
        If the address string does not match any known pattern.
    """
    addr = address.strip()

    # --- Data block ---
    m = _RE_DB.match(addr)
    if m:
        db = int(m.group("db"))
        type_str = m.group("type").upper()
        byte_off = int(m.group("byte"))
        bit_pos = int(m.group("bit")) if m.group("bit") is not None else 0
        word_len, size = _TYPE_TO_WORDLEN[type_str]
        return S7Address(
            area=S7Area.DB,
            word_len=word_len,
            db_number=db,
            start=byte_off,
            bit=bit_pos,
            size=size,
        )

    # --- Memory area (M, MW, MD, MB) ---
    m = _RE_M.match(addr)
    if m:
        subtype = (m.group("subtype") or "").upper()
        byte_off = int(m.group("byte"))
        bit_pos = int(m.group("bit")) if m.group("bit") is not None else 0

        if subtype == "W":
            return S7Address(S7Area.MK, S7WordLen.WORD, 0, byte_off, 0, 2)
        elif subtype == "D":
            return S7Address(S7Area.MK, S7WordLen.DWORD, 0, byte_off, 0, 4)
        elif subtype == "B":
            return S7Address(S7Area.MK, S7WordLen.BYTE, 0, byte_off, 0, 1)
        else:
            # Plain M<byte>.<bit> -- single bit in merker byte
            return S7Address(S7Area.MK, S7WordLen.BIT, 0, byte_off, bit_pos, 1)

    # --- Process input / output words ---
    m = _RE_IQ.match(addr)
    if m:
        area_char = m.group("area").upper()
        subtype = m.group("subtype").upper()
        byte_off = int(m.group("byte"))
        area = S7Area.PE if area_char == "I" else S7Area.PA
        if subtype == "W":
            return S7Address(area, S7WordLen.WORD, 0, byte_off, 0, 2)
        elif subtype == "D":
            return S7Address(area, S7WordLen.DWORD, 0, byte_off, 0, 4)
        else:
            return S7Address(area, S7WordLen.BYTE, 0, byte_off, 0, 1)

    raise ValueError(
        f"Cannot parse PLC address '{address}'. "
        "Expected formats: 'DB1,REAL4', 'DB1,BOOL0.3', 'MW10', 'MD12', 'MB4', 'M0.5', 'IW0', 'QW2'."
    )
