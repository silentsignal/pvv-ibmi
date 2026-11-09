#!/usr/bin/env python3
"""Reconstruct the IBM i 7.5 PVV canonical message and descriptor.

``pvv_demo.py`` supplies saved-program bytes through a sparse address-space
adapter.  This module can also be run directly against a retained DAD program
dump.  Unsupported structures fail closed instead of being guessed or omitted.
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import re
import struct
import sys
from dataclasses import dataclass
from pathlib import Path


LINE_RE = re.compile(
    r"^([0-9A-F]{10}) ([0-9A-F]{6}) \+[0-9A-F]{4}\s+"
    r"((?:[0-9A-F]{16}\s+){3}[0-9A-F]{16})"
)
REPEAT_RE = re.compile(
    r"^\s*(\d+) LINES ([0-9A-F]{10}) ([0-9A-F]{6}) \+[0-9A-F]{4} "
    r"TO ([0-9A-F]{10}) ([0-9A-F]{6})"
)


class DumpError(RuntimeError):
    pass


@dataclass(frozen=True)
class Chunk:
    label: str
    data: bytes
    source_pointer: int | None
    construction: str
    transformed_offsets: tuple[int, ...] = ()
    aggregate_delivery: str = "COPIED_INTO_AGGREGATE_STORAGE"


class DADProgramDump:
    """Sparse reader for DAD's 10-hex segment + 6-hex offset format."""

    def __init__(self, path: Path):
        self.path = path
        self.lines: dict[tuple[int, int], bytes] = {}
        previous: bytes | None = None
        for text in path.read_text(errors="replace").splitlines():
            match = LINE_RE.match(text)
            if match:
                segment = int(match.group(1), 16)
                offset = int(match.group(2), 16)
                previous = bytes.fromhex("".join(match.group(3).split()))
                self.lines[segment, offset] = previous
                continue
            match = REPEAT_RE.match(text)
            if match and previous is not None:
                segment = int(match.group(2), 16)
                offset = int(match.group(3), 16)
                end_segment = int(match.group(4), 16)
                end_offset = int(match.group(5), 16)
                if segment != end_segment:
                    raise DumpError("cross-segment SAME AS ABOVE range")
                while offset <= end_offset:
                    self.lines[segment, offset] = previous
                    offset += 0x20
        if not self.lines:
            raise DumpError(f"no DAD data lines in {path}")

    @staticmethod
    def pointer(segment: int, offset: int) -> int:
        if segment >= 1 << 40 or offset >= 1 << 24:
            raise DumpError("DAD segmented address outside 40+24-bit format")
        return (segment << 24) | offset

    def read(self, pointer: int, length: int) -> bytes:
        segment, offset = pointer >> 24, pointer & 0xFFFFFF
        result = bytearray()
        while length:
            line_offset = offset & ~0x1F
            line = self.lines.get((segment, line_offset))
            if line is None:
                raise DumpError(
                    f"unmapped DAD range {segment:010X} {offset:06X}"
                )
            within = offset - line_offset
            count = min(length, 0x20 - within)
            result += line[within : within + count]
            offset += count
            length -= count
        return bytes(result)

    def u16(self, pointer: int) -> int:
        return int.from_bytes(self.read(pointer, 2), "big")

    def u32(self, pointer: int) -> int:
        return int.from_bytes(self.read(pointer, 4), "big")

    def u64(self, pointer: int) -> int:
        return int.from_bytes(self.read(pointer, 8), "big")


class V7R5ProgramValidation:
    """Recovered PVV message, descriptor, and HMAC calculation.

    The implementation covers the saved-program layout recovered from the
    matched IBM i 7.5 LIC path.  Every unsupported branch raises ``DumpError``
    rather than producing a partial validation value.
    """

    # VBN seed alternatives constructed at media C91FAB68..C91FAC84.
    KEY8_ALTERNATIVES = tuple(
        bytes.fromhex(value)
        for value in (
            "20955C8920F48730", "7B87309559C820F4",
            "A320F487309EE9C8", "E9C8F487309EB561",
            "B561E9C8D034309E", "309EE9C86298D034",
            "D034305819C86298", "6298D03430ABB1C8",
            "B1C8629F473430AB", "30ABB1C862E90734",
            "073432CE8C862E91", "2E9132CE813F75B2",
        )
    )

    # Media C91FAD14..C91FAD58 selects the release-specific 64-bit value.
    # rldimi(..., 32, 0) inserts the second constructed word as bits 0..31,
    # yielding these big-endian 64-bit values.
    VERSION_KEYS = {
        0x0110: bytes.fromhex("A62800044CF55069"),
        0x0112: bytes.fromhex("A62800044CF55069"),
        0x0120: bytes.fromhex("A62800044CF55069"),
        0x0130: bytes.fromhex("A62800044CF55069"),
        0x0210: bytes.fromhex("28C3E7044CF540A6"),
        0x0211: bytes.fromhex("28C3E7044CF540A6"),
        0x0220: bytes.fromhex("28C3E7044CF540A6"),
        0x0230: bytes.fromhex("28C3E7044CF540A6"),
        0x0305: bytes.fromhex("C3E709116CF53028"),
        0x0310: bytes.fromhex("C3E709116CF53028"),
        0x0320: bytes.fromhex("C3E709116CF53028"),
        0x0360: bytes.fromhex("E702F61B6CF520C3"),
        0x0370: bytes.fromhex("02F609876CF510E7"),
        0x0410: bytes.fromhex("F60D11476CF45002"),
        0x0414: bytes.fromhex("3E2811476CF440F6"),
        0x0420: bytes.fromhex("289159176CF4303E"),
        0x0430: bytes.fromhex("91591BE27CF42028"),
        0x0440: bytes.fromhex("5918D7A27CF41491"),
        0x0450: bytes.fromhex("170C77A27CF41059"),
        0x0510: bytes.fromhex("0C36EA327CF37017"),
        0x0520: bytes.fromhex("4436E3079CF3600C"),
        0x0530: bytes.fromhex("B935A0079CF31044"),
        0x0540: bytes.fromhex("D235E7589CF210B9"),
        0x0550: bytes.fromhex("387209589CF110D2"),
        0x0610: bytes.fromhex("9170C958061010D2"),
        0x0710: bytes.fromhex("3826DD881B8934F0"),
        0x0720: bytes.fromhex("B9385CCDF3829336"),
        0x0730: bytes.fromhex("600B14C009543E00"),
        0x0740: bytes.fromhex("7C3208AB38920932"),
        0x0750: bytes.fromhex("83CF578390004BA1"),
    }
    MODE_KEYS = {
        1: bytes.fromhex("3809245098034DDE"),
        2: bytes.fromhex("3809745098034DDE"),
        3: bytes.fromhex("3609745098921DDE"),
        4: bytes.fromhex("2809745098921BCA"),
    }

    def __init__(self, dump: DADProgramDump):
        self.dump = dump
        # The base segment header is identified by its DAD base-segment marker.
        candidates = [seg for seg, off in dump.lines if off == 0]
        self.base_segment = next(
            (seg for seg in candidates if dump.read(dump.pointer(seg, 0), 2) == b"\x00\x01"),
            None,
        )
        if self.base_segment is None:
            raise DumpError("base MI program segment was not found")
        self.base = dump.pointer(self.base_segment, 0)
        self.header = dump.u64(self.base + 0x70)
        self.pointer_table = dump.u64(self.header + 0x10)
        count = dump.u32(self.pointer_table + 4)
        if not 1 <= count <= 256:
            raise DumpError(f"implausible segment-table count {count}")
        self.segment_bases = [
            dump.u64(self.pointer_table + 0x10 + index * 0x30)
            for index in range(count)
        ]
        self.chunks: list[Chunk] = []

    def canonicalize(self, pointer: int) -> int:
        if pointer == 0:
            return 0
        for index, base in enumerate(self.segment_bases, 1):
            if pointer >> 24 == base >> 24 and pointer >= base:
                offset = pointer - base
                if offset <= 0xFFFFFFFF:
                    return (index << 32) | offset
        raise DumpError(f"pointer {pointer:016X} is absent from the VBN segment table")

    def resolve_canonical(self, pointer: int) -> int:
        if pointer == 0:
            return 0
        index, offset = pointer >> 32, pointer & 0xFFFFFFFF
        if not 1 <= index <= len(self.segment_bases):
            raise DumpError(f"canonical segment index {index} is invalid")
        return self.segment_bases[index - 1] + offset

    def append(self, label: str, pointer: int | None = None,
               length: int | None = None, data: bytes | bytearray | None = None,
               construction: str | None = None,
               transformed_offsets: tuple[int, ...] = ()) -> None:
        source_span = data is None
        if source_span:
            if pointer is None or length is None:
                raise TypeError("append requires pointer+length or data")
            data = self.dump.read(pointer, length)
            construction = construction or "direct dump span"
        else:
            construction = construction or "constructed bytes"
        # C7895974 tail-calls copying helper C78957B4 below 0x400 bytes. At
        # 0x400 and above it records the original pointer and length instead.
        # Constructed/canonicalized spans already reside in private storage.
        aggregate_delivery = (
            "RETAINED_SOURCE_POINTER"
            if source_span and len(data) >= 0x400
            else "COPIED_INTO_AGGREGATE_STORAGE"
        )
        self.chunks.append(Chunk(
            label, bytes(data), pointer, construction, transformed_offsets,
            aggregate_delivery,
        ))

    def append_blob(self, label: str, pointer: int) -> None:
        length = self.dump.u32(pointer)
        if length <= 0:
            return
        self.append(label, pointer, length, construction="length-prefixed blob including u32 length")

    def _canonicalized_copy(
        self,
        pointer: int,
        length: int,
        offsets: tuple[int, ...],
    ) -> bytes:
        """Copy a span and replace each non-null pointer with its VBN form."""
        copied = bytearray(self.dump.read(pointer, length))
        for offset in offsets:
            if offset < 0 or offset + 8 > length:
                raise DumpError(
                    f"canonical pointer offset {offset:#x} is outside {length:#x}-byte span"
                )
            value = int.from_bytes(copied[offset : offset + 8], "big")
            if value:
                copied[offset : offset + 8] = self.canonicalize(value).to_bytes(8, "big")
        return bytes(copied)

    def _append_pointer_record_array(
        self,
        label: str,
        pointer: int,
        count: int,
        record_size: int,
        pointer_offsets: tuple[int, ...],
    ) -> None:
        """Append a fixed-record array after canonicalizing embedded pointers."""
        if not pointer:
            if count:
                raise DumpError(f"{label} has count {count} but a null pointer")
            return
        length = count * record_size
        offsets = tuple(
            record * record_size + field
            for record in range(count)
            for field in pointer_offsets
        )
        self.append(
            label,
            pointer=pointer,
            data=self._canonicalized_copy(pointer, length, offsets),
            construction="fixed-record array with canonical pointer substitution",
            transformed_offsets=offsets,
        )

    def _primary_blob_fix_offsets(self, fix_list: int, addend: int = 0) -> list[int]:
        """Decode a C91FB504 primary-blob pointer-fix list.

        The list has a u32 count at +4. One-based 0x10-byte entries begin at
        +0x10 and carry the blob-relative u32 offset at entry+4.  The list at
        entry+0x98 applies an additional +8 before pointer canonicalization;
        the +0x50 and +0x58 lists use the recorded offset directly.
        """
        if not fix_list:
            return []
        count = self.dump.u32(fix_list + 4)
        if count > 0x100000:
            raise DumpError(f"implausible primary-blob fix-list count {count}")
        return [
            self.dump.u32(fix_list + ordinal * 0x10 + 4) + addend
            for ordinal in range(1, count + 1)
        ]

    def _append_primary_blob(self, label: str, entry: int) -> None:
        """Media C91FB504: append entry+0x70 blob with pointer fixups."""
        d = self.dump
        blob = d.u64(entry + 0x70)
        if not blob:
            return
        length = d.u32(blob)
        if length <= 0:
            return
        offsets = [
            *self._primary_blob_fix_offsets(d.u64(entry + 0x50)),
            *self._primary_blob_fix_offsets(d.u64(entry + 0x58)),
            *self._primary_blob_fix_offsets(d.u64(entry + 0x98), addend=8),
        ]
        if not offsets:
            self.append_blob(label, blob)
            return
        if len(set(offsets)) != len(offsets):
            raise DumpError("overlapping C91FB504 primary-blob fix offsets")
        copied = self._canonicalized_copy(blob, length, tuple(offsets))
        self.append(
            label,
            pointer=blob,
            data=copied,
            construction=(
                "length-prefixed primary blob copied; C91FB504 +50/+58 "
                "offsets and +98 offsets+8 canonicalized"
            ),
            transformed_offsets=tuple(offsets),
        )

    def _build_validation_component_tail(self, entries: list[int]) -> None:
        """Media C91FD114: append the final validation-component aggregate.

        This routine was absent from the original 5,684-byte reconstruction.
        It serializes the component descriptor rooted at header+0x18, its
        subordinate arrays, per-entry record pointers, and the procedure
        fragments rooted through header+0xD0.  Unsupported branches fail
        closed instead of producing a plausible but incomplete digest input.
        """
        d, h = self.dump, self.header
        segment_table = self.pointer_table
        component = d.u64(h + 0x18)
        mode = d.read(h + 0x90, 1)[0]

        self.append(
            "tail.canonical(header)",
            pointer=h,
            data=self.canonicalize(h).to_bytes(8, "big"),
            construction="canonicalized program-header pointer (C91FD190..294)",
            transformed_offsets=(0,),
        )
        if mode not in (1, 2, 3, 4):
            raise DumpError(f"C91FD114 mode {mode} is not implemented")
        if mode not in (2, 4):
            self.append(
                "tail.canonical(component+0)",
                pointer=component,
                data=self.canonicalize(d.u64(component)).to_bytes(8, "big"),
                construction="canonicalized component pointer (C91FD2B4..3A4)",
                transformed_offsets=(0,),
            )
        elif mode == 4:
            mode4 = d.u64(component + 0xE0)
            if mode4:
                count = d.u32(mode4 + 4)
                for ordinal in range(1, count + 1):
                    item = d.u64(mode4 + ordinal * 0x10)
                    self.append(
                        f"tail.mode4-item{ordinal}", item, d.u32(item + 8),
                    )

        # C91FB7B4: the 0x128-byte component descriptor itself.
        component_pointer_offsets = (
            0x00, 0x10, 0x18, 0x28, 0x30, 0x50, 0x58, 0x70,
            0x78, 0x90, 0xA0, 0xA8, 0xB8, 0xC0, 0xD0, 0xD8,
            0xE0, 0xE8, 0xF0,
        )
        component_bytes = self._canonicalized_copy(
            component, 0x128, component_pointer_offsets
        )
        self.append(
            "tail.component-descriptor",
            pointer=component,
            data=component_bytes,
            construction="0x128-byte descriptor with canonical pointer substitution",
            transformed_offsets=component_pointer_offsets,
        )

        # C91FB9A4: 16-byte records; type 0x0B carries a pointer at +8.
        pointer = d.u64(component + 0x10)
        count = d.u32(component + 0x20)
        if pointer:
            copied = bytearray(d.read(pointer, count * 0x10))
            changed: list[int] = []
            for index in range(count):
                record = index * 0x10
                if copied[record + 4] == 0x0B:
                    value = int.from_bytes(copied[record + 8 : record + 0x10], "big")
                    if value:
                        copied[record + 8 : record + 0x10] = self.canonicalize(value).to_bytes(8, "big")
                        changed.append(record + 8)
            self.append(
                "tail.component+10-array",
                pointer=pointer,
                data=copied,
                construction="16-byte records; type-0x0B pointers canonicalized",
                transformed_offsets=tuple(changed),
            )
        elif count:
            raise DumpError("component+0x10 array has count but no pointer")

        # C91FBAA4.
        self._append_pointer_record_array(
            "tail.component+28-array", d.u64(component + 0x28),
            d.u32(component + 0x24), 0x20, (0x08,),
        )

        # C91FBED4 and C91FBBD4/C91FBC04/C91FBD34/C91FBD74/C91FBDA4.
        records = d.u64(component + 0x30)
        record_count = d.u32(component + 0x38)
        if records:
            primary_offsets = tuple(
                index * 0x50 + field
                for index in range(record_count)
                for field in (0x10, 0x18, 0x28, 0x30, 0x40)
            )
            self.append(
                "tail.component+30-records",
                pointer=records,
                data=self._canonicalized_copy(records, record_count * 0x50, primary_offsets),
                construction="0x50-byte records with five canonical pointer fields",
                transformed_offsets=primary_offsets,
            )
            for index in range(record_count):
                record = records + index * 0x50
                self._append_pointer_record_array(
                    f"tail.component+30.record{index + 1}.child10",
                    d.u64(record + 0x10), d.u32(record + 0x08), 0x10, (),
                )
                self._append_pointer_record_array(
                    f"tail.component+30.record{index + 1}.child18",
                    d.u64(record + 0x18), d.u32(record + 0x0C), 0x10, (0,),
                )
                child28 = d.u64(record + 0x28)
                child28_count = d.u32(record + 0x20)
                if child28:
                    self.append(
                        f"tail.component+30.record{index + 1}.child28",
                        child28, child28_count * 0x0C,
                    )
                elif child28_count:
                    raise DumpError("component+30 child28 has count but no pointer")
                child30 = d.u64(record + 0x30)
                child30_count = d.u32(record + 0x24)
                if child30:
                    self.append(
                        f"tail.component+30.record{index + 1}.child30",
                        child30, child30_count * 8,
                    )
                elif child30_count:
                    raise DumpError("component+30 child30 has count but no pointer")
                self._append_pointer_record_array(
                    f"tail.component+30.record{index + 1}.child40",
                    d.u64(record + 0x40), d.u32(record + 0x38), 0x20, (0x18,),
                )
        elif record_count:
            raise DumpError("component+0x30 records have count but no pointer")

        # Remaining component arrays, in the exact C91FD41C..544 order.
        self._append_pointer_record_array(
            "tail.component+50-array", d.u64(component + 0x50),
            d.u32(component + 0x4C), 0x10, (0,),
        )
        for label, pointer_offset, count_offset, record_size in (
            ("tail.component+58-array", 0x58, 0x60, 8),
            ("tail.component+70-array", 0x70, 0x6C, 8),
        ):
            pointer = d.u64(component + pointer_offset)
            count = d.u32(component + count_offset)
            if pointer:
                self.append(label, pointer, count * record_size)
            elif count:
                raise DumpError(f"{label} has count but no pointer")
        self._append_pointer_record_array(
            "tail.component+78-array", d.u64(component + 0x78),
            d.u32(component + 0x80), 0x18, (0, 8),
        )
        self._append_pointer_record_array(
            "tail.component+90-array", d.u64(component + 0x90),
            d.u32(component + 0x98), 0x18, (0,),
        )
        for label, pointer_offset, count_offset, record_size in (
            ("tail.component+A0-array", 0xA0, 0x9C, 8),
            ("tail.component+A8-array", 0xA8, 0xB0, 0x10),
            ("tail.component+B8-array", 0xB8, 0xB4, 8),
        ):
            pointer = d.u64(component + pointer_offset)
            count = d.u32(component + count_offset)
            if pointer:
                self.append(label, pointer, count * record_size)
            elif count:
                raise DumpError(f"{label} has count but no pointer")
        self._append_pointer_record_array(
            "tail.component+C0-array", d.u64(component + 0xC0),
            d.u32(component + 0xC8), 0x20, (0,),
        )
        self._append_pointer_record_array(
            "tail.component+D0-array", d.u64(component + 0xD0),
            d.u32(component + 0xCC), 0x18, (0,),
        )
        pointer = d.u64(component + 0xF0)
        if pointer:
            self.append("tail.component+F0-array", pointer, d.u32(component + 0x9C) * 4)

        # C91FC9B4: append the fixed final descriptor.
        final_descriptor = d.u64(h + 0xF0)
        if not final_descriptor:
            raise DumpError("header+0xF0 final descriptor is null")
        self.append("tail.header+F0-descriptor", final_descriptor, 0x78)

        # C91FC9E4: +0x30 is a canonical segmented reference. Resolve it,
        # copy component+0x08 bytes plus a 0x30-byte prefix, canonicalize the
        # pointer at +0 and every complete 64-bit value in the variable tail, append.
        optional_reference = d.u64(final_descriptor + 0x30)
        if optional_reference:
            optional = self.resolve_canonical(optional_reference)
            variable_length = d.u32(component + 8)
            total_length = variable_length + 0x30
            pointer_offsets = (0, *range(0x30, 0x30 + (variable_length // 8) * 8, 8))
            self.append(
                "tail.header+F0-optional",
                pointer=optional,
                data=self._canonicalized_copy(optional, total_length, pointer_offsets),
                construction=(
                    "C91FC9E4 resolved canonical reference; +0 and variable "
                    "64-bit tail canonicalized"
                ),
                transformed_offsets=tuple(pointer_offsets),
            )

        # C91FCBA4: one canonical pointer for each entry validation record.
        for entry_number, entry in enumerate(entries, 1):
            validation_records = d.u64(entry + 0x68)
            if not validation_records:
                continue
            count = d.u32(validation_records + 4)
            for ordinal in range(1, count + 1):
                record = validation_records + ordinal * 0x90 - 0x80
                value = d.u64(record + 0x10)
                self.append(
                    f"tail.entry{entry_number}.record{ordinal}.canonical+10",
                    pointer=record + 0x10,
                    data=self.canonicalize(value).to_bytes(8, "big") if value else b"\0" * 8,
                    construction="canonicalized validation-record pointer",
                    transformed_offsets=(0,),
                )

        # C91FCD74: procedure fragments referenced by the header+D0 root.
        root = d.u64(d.u64(h + 0xD0)) if d.u64(h + 0xD0) else 0
        visited_roots: set[int] = set()
        while root:
            if root in visited_roots:
                raise DumpError("C91FCD74 procedure-root list contains a cycle")
            visited_roots.add(root)

            # C91FCD8C tests byte +0x10 and skips non-type-1 nodes, then
            # C91FD0A4 advances through the link at +0x08.  CALLAES has a
            # type-1 node followed by a type-2 node; the latter contributes no
            # chunks on this path but must not terminate or invalidate the
            # list traversal.
            if d.read(root + 0x10, 1)[0] != 1:
                root = d.u64(root + 8)
                continue
            count = d.u32(root + 4)
            for ordinal in range(1, count + 1):
                record = root + ordinal * 0x18
                canonical_source = d.u64(record + 8)
                source = self.resolve_canonical(canonical_source) if canonical_source else 0
                length = d.u32(record + 0x18)
                flag = d.read(record + 0x1C, 1)[0]
                if not source or length < 8:
                    raise DumpError("C91FCD74 procedure fragment is null or too short")
                copied = bytearray(d.read(source, length))
                if flag == 0:
                    raise DumpError(
                        "C91FCD74 flag-zero branch requires unresolved C750B294 result"
                    )
                tail_pointer = int.from_bytes(copied[-8:], "big")
                if tail_pointer:
                    copied[-8:] = self.canonicalize(tail_pointer).to_bytes(8, "big")
                self.append(
                    f"tail.procedure-fragment{ordinal}",
                    pointer=source,
                    data=copied,
                    construction="procedure fragment with final pointer canonicalized",
                    transformed_offsets=(length - 8,),
                )

                # C91FD00C..C91FD098 resolves the second canonical reference
                # in the 0x18-byte root record.  LIC appends the referenced
                # structure through byte ``u32(+0x1C) + 0x0C`` and then calls
                # C78959C4 on output+8, canonicalizing its embedded pointer.
                # This is a distinct chunk following each procedure fragment;
                # omitting it truncates CALLAES by 7 * 0x70 bytes.
                secondary_reference = d.u64(record + 0x10)
                if not secondary_reference:
                    raise DumpError(
                        "C91FCD74 secondary canonical reference is null"
                    )
                secondary = self.resolve_canonical(secondary_reference)
                secondary_length = d.u32(secondary + 0x1C) + 0x0C
                if secondary_length < 0x10:
                    raise DumpError(
                        "C91FCD74 secondary structure is too short for +8 pointer"
                    )
                secondary_copy = bytearray(
                    d.read(secondary, secondary_length)
                )
                secondary_pointer = int.from_bytes(
                    secondary_copy[8:16], "big"
                )
                if secondary_pointer:
                    secondary_copy[8:16] = self.canonicalize(
                        secondary_pointer
                    ).to_bytes(8, "big")
                self.append(
                    f"tail.procedure-secondary{ordinal}",
                    pointer=secondary,
                    data=secondary_copy,
                    construction=(
                        "secondary procedure structure through +0x1C+0x0C; "
                        "pointer at +8 canonicalized"
                    ),
                    transformed_offsets=(8,),
                )

            root = d.u64(root + 8)

    def _build_entry_auxiliary(self, entry: int, entry_number: int) -> None:
        """Media C9202A44: canonicalize and append one program entry."""
        d = self.dump
        structure = d.u64(entry + 0xC8)
        if structure:
            for offset in (0x08, 0x18):
                blob = d.u64(structure + offset)
                if blob:
                    self.append_blob(f"entry{entry_number}.structure+{offset:X}", blob)

        records = d.u64(entry + 0x68)
        auxiliary = d.u64(structure + 0x10) if structure else 0
        if records:
            for ordinal in range(1, d.u32(records + 4) + 1):
                record = records + ordinal * 0x90 - 0x80
                length = d.u32(record + 8)
                data_pointer = d.u64(record + 0x20)
                if length < 0x10:
                    raise DumpError("VBN record length is smaller than canonical tail")
                self.append(
                    f"entry{entry_number}.record{ordinal}.data-head",
                    data_pointer, length - 0x10,
                )
                tail = bytearray(d.read(data_pointer + length - 0x10, 0x10))
                tail[8:16] = self.canonicalize(
                    int.from_bytes(tail[8:16], "big")
                ).to_bytes(8, "big")
                self.append(
                    f"entry{entry_number}.record{ordinal}.data-tail",
                    pointer=data_pointer + length - 0x10,
                    data=tail,
                    construction="copied span with canonical pointer substitution",
                    transformed_offsets=(8,),
                )

                if auxiliary:
                    item = auxiliary + ordinal * 0x60 - 0x50
                    item_length = d.u32(item + 0x0C)
                    item_pointer = d.u64(item + 0x10)
                    copied = bytearray(d.read(item_pointer, item_length))
                    if item_length < 0x38:
                        raise DumpError("VBN auxiliary record lacks canonical pointer fields")
                    for offset in (8, 0x30):
                        copied[offset:offset + 8] = self.canonicalize(
                            int.from_bytes(copied[offset:offset + 8], "big")
                        ).to_bytes(8, "big")
                    self.append(
                        f"entry{entry_number}.record{ordinal}.auxiliary",
                        pointer=item_pointer,
                        data=copied,
                        construction="copied span with two canonical pointer substitutions",
                        transformed_offsets=(8, 0x30),
                    )

                blob = d.u64(record + 0x28)
                if blob:
                    self.append_blob(f"entry{entry_number}.record{ordinal}.blob", blob)
                self.append(
                    f"entry{entry_number}.record{ordinal}.field+6", record + 6, 2
                )
                reference = d.u64(record + 0x48)
                if reference:
                    self.append_blob(
                        f"entry{entry_number}.record{ordinal}.reference",
                        self.resolve_canonical(reference),
                    )

        if structure:
            reference = d.u64(structure + 0xA0)
            if reference:
                self.append_blob(
                    f"entry{entry_number}.structure-reference",
                    self.resolve_canonical(reference),
                )

    def build_message(self) -> bytes:
        """Build the byte stream in BNOBJCAL physical aggregate-entry order.

        The VBN builder's calls do *not* directly define digest order once a
        source span reaches C7895974's 0x400 retained-pointer path. C78957B4
        keeps an independent index at aggregate+8 for its owned copy buffer;
        later copied appends continue extending that same entry even after a
        retained entry was added to the aggregate's pointer/length array.
        BNOBJCAL then walks the physical array. For all presently observed
        (< arena-boundary) V7R5 objects this is one concatenated copied-byte
        entry followed by retained spans in append order.
        """
        d, h = self.dump, self.header
        self.chunks.clear()
        self.append("header+5B", h + 0x5B, 1)
        # C91FD734..75C derives this representation from base/control bit 0.
        state = b"\x80\x00" if d.read(self.base + 0x20, 1)[0] & 1 else b"\x00\x01"
        self.append("derived-state", data=state, construction="derived from base+0x20 bit 0")
        for label, offset, length in (
            ("header+5C", 0x5C, 2), ("header+90", 0x90, 1),
            ("header+A8", 0xA8, 4),
        ):
            self.append(label, h + offset, length)
        for offset in (0x08, 0x10, 0x18, 0x28, 0xD0, 0xD8, 0xE0, 0xF0):
            value = self.canonicalize(d.u64(h + offset)).to_bytes(8, "big")
            self.append(
                f"canonical(header+{offset:X})",
                pointer=h + offset,
                data=value,
                construction="canonicalized tagged pointer",
                transformed_offsets=(0,),
            )

        d0 = d.u64(h + 0xD0)
        version_block = d.u64(h + 8)
        entries_block = d.u64(h + 0xE0)
        self.append("header+D0->+50", d0 + 0x50, 0x10)
        self.append("header+D0->+60", d0 + 0x60, 0x20)
        self.append("version+1", version_block + 1, 1)
        self.append("version+6", version_block + 6, 2)

        entry_count = d.u32(entries_block + 4)
        entries: list[int] = []
        for ordinal in range(1, entry_count + 1):
            entry = d.u64(entries_block + ordinal * 0x30 - 0x20)
            entries.append(entry)
            self.append(f"entry{ordinal}+2", entry + 2, 2)
            # C91FE058 initializes r29 to 1 once before the loop.  The
            # C91FE0A0 call supplies that invariant r29 as the length; r31 is
            # the separately incremented entry ordinal.  Treating the length
            # as the ordinal corrupts every object with more than one entry.
            self.append(f"entry{ordinal}+C3", entry + 0xC3, 1)

        # C91FB504. Each entry contributes a length-prefixed primary blob;
        # three optional lists identify embedded pointer fields that LIC
        # canonicalizes in a private copy before appending.
        for ordinal, entry in enumerate(entries, 1):
            self._append_primary_blob(f"entry{ordinal}.primary-blob", entry)

        blob = d.u64(h + 0x28)
        if blob:
            self.append_blob("header+28-blob", blob)
        for ordinal, entry in enumerate(entries, 1):
            self._build_entry_auxiliary(entry, ordinal)
            for offset in (0x78, 0x80):
                blob = d.u64(entry + offset)
                if blob:
                    self.append_blob(f"entry{ordinal}+{offset:X}-blob", blob)
        self._build_validation_component_tail(entries)
        return self.aggregate_message()

    def aggregate_ordered_chunks(self) -> list[Chunk]:
        """Return chunks in the recovered BNOBJCAL physical-entry order."""
        copied = [
            chunk for chunk in self.chunks
            if chunk.aggregate_delivery == "COPIED_INTO_AGGREGATE_STORAGE"
        ]
        retained = [
            chunk for chunk in self.chunks
            if chunk.aggregate_delivery == "RETAINED_SOURCE_POINTER"
        ]
        return copied + retained

    def aggregate_message(self) -> bytes:
        return b"".join(chunk.data for chunk in self.aggregate_ordered_chunks())

    def compared_value(self) -> bytes:
        """Collect the four 64-bit values compared by the live vbnspnt2 PVV gate.

        In a live materialized program these are the expected VBN.  SAVE1 and
        its matching recompiled live CALLAES image have identical segment
        identities, canonical message, descriptor, and all four values. This
        proves that the structurally corresponding SAVOBJ fields directly
        store the VBN for this V7R5 layout.  The earlier contrary conclusion
        compared SAVE1 to a different live CALLAES build.
        """
        return b"".join(
            self.dump.read(address, 8)
            for _, address in self.compared_field_addresses()
        )

    def compared_field_addresses(self) -> tuple[tuple[str, int], ...]:
        """Recover the exact four vbnspnt2 comparison operands.

        The first operand is not intrinsically ``header+0x2c0``.  At live
        C91F6790..C91F67DC, vbnspnt2 reads the canonical reference at
        ``*(header+0xd0)+0x80``, resolves it through the program segment
        directory, and then compares ``resolved+0x10``.  It happened to equal
        ``header+0x2c0`` in the original CALLAES calibration object.
        """
        d, h = self.dump, self.header
        version_block = d.u64(h + 8)
        comparison_version = d.u16(version_block + 8)
        d0 = d.u64(h + 0xD0)
        canonical_reference = d.u64(d0 + 0x80)
        if comparison_version < 0x0550 or canonical_reference >> 32 == 0:
            raise DumpError(
                "vbnspnt2 first comparison operand uses the unresolved "
                f"pre-0x0550/null-reference branch (version={comparison_version:04X})"
            )
        first = self.resolve_canonical(canonical_reference) + 0x10
        return (
            ("resolve_canonical(*(program_header+0xD0)+0x80)+0x10", first),
            ("*(program_header+0xF0)+0x78", d.u64(h + 0xF0) + 0x78),
            ("*(program_header+0xD0)+0xF8", d0 + 0xF8),
            ("*(program_header+0x18)+0x128", d.u64(h + 0x18) + 0x128),
        )

    def structure_summary(self) -> dict:
        """Return the structural loop counts used by the recovered VBN walk.

        These are *inputs to one observed object-level VBN calculation*, not
        evidence that each subordinate entry/record carries an independent
        PVV.  Keeping that distinction explicit prevents a multi-module
        program from being incorrectly reported as having one PVV per entry.
        """
        d, h = self.dump, self.header
        entries_block = d.u64(h + 0xE0)
        entry_count = d.u32(entries_block + 4)
        entries = [
            d.u64(entries_block + ordinal * 0x30 - 0x20)
            for ordinal in range(1, entry_count + 1)
        ]
        per_entry_record_counts = []
        for entry in entries:
            records = d.u64(entry + 0x68)
            per_entry_record_counts.append(d.u32(records + 4) if records else 0)
        component = d.u64(h + 0x18)
        version_block = d.u64(h + 8)
        return {
            "version": f"0x{d.u16(version_block + 6):04X}",
            "mode": d.read(h + 0x90, 1)[0],
            "segment_table_count": len(self.segment_bases),
            "program_entry_count": entry_count,
            "per_entry_subordinate_record_counts": per_entry_record_counts,
            "subordinate_record_total": sum(per_entry_record_counts),
            "component_record_count": d.u32(component + 0x38),
            "classification": (
                "structural inputs to the observed object-level VBN; "
                "not independent PVV-record counts"
            ),
            "confidence": "CONFIRMED",
        }

    def expected_value(self) -> bytes:
        """Deprecated alias for the stored four-value comparison result.

        Use :meth:`calculate` for the independently computed descriptor-keyed
        HMAC.  This alias remains only for callers that need the saved value.
        """
        return self.compared_value()

    def descriptor_candidates(self):
        d, h = self.dump, self.header
        # The first eight descriptor bytes come from two program-validation
        # fields.  They are material passed to the factory-created algorithm
        # object's vtable[1] method; they are not the provider pointer.
        validation_fields = struct.pack(">II", d.u32(h + 0xCC), d.u32(h + 0xA4))
        version = d.u16(d.u64(h + 8) + 6)
        mode = d.read(h + 0x90, 1)[0]
        if version not in self.VERSION_KEYS or mode not in self.MODE_KEYS:
            raise DumpError(f"unsupported VBN seed version={version:04X} mode={mode}")
        for index, selector_qword in enumerate(self.KEY8_ALTERNATIVES):
            yield (
                index,
                validation_fields
                + selector_qword
                + self.VERSION_KEYS[version]
                + self.MODE_KEYS[mode],
            )

    def descriptor_selector(self) -> dict:
        """Implement media C91FAC88..C91FACE8 exactly.

        SELRI BI=38 is equality-select in this sequence: select the register
        operand when EQ is true and the immediate operand otherwise.
        The three contributions are scaled by 4, 1, and 2 64-bit units.
        """
        d, h = self.dump, self.header
        header_5c = d.u16(h + 0x5C)
        if header_5c == 0:
            selector_0 = 1
        elif header_5c == 0x80:
            selector_0 = 0
        else:
            selector_0 = 2

        version_block = d.u64(h + 8)
        version_kind = d.u16(version_block + 0x20)
        selector_12 = 0 if version_kind == 0x28 else 1

        base_flags = d.read(self.base + 0x20, 1)[0]
        selector_7 = 1 if (base_flags & 1) == 0 else 0
        index = selector_12 + 4 * selector_0 + 2 * selector_7
        if not 0 <= index < len(self.KEY8_ALTERNATIVES):
            raise DumpError(f"descriptor selector index {index} is invalid")
        return {
            "index": index,
            "byte_offset": index * 8,
            "header_5c": header_5c,
            "version_kind": version_kind,
            "base_flags": base_flags,
            "terms": {"r0_times_4": selector_0 * 4,
                      "r12": selector_12,
                      "r7_times_2": selector_7 * 2},
            "evidence": "media C91FAC88..C91FACE8",
            "confidence": "CONFIRMED",
        }

    def selected_descriptor(self) -> tuple[dict, bytes]:
        d, h = self.dump, self.header
        selector = self.descriptor_selector()
        validation_fields = struct.pack(">II", d.u32(h + 0xCC), d.u32(h + 0xA4))
        version = d.u16(d.u64(h + 8) + 6)
        mode = d.read(h + 0x90, 1)[0]
        if version not in self.VERSION_KEYS or mode not in self.MODE_KEYS:
            raise DumpError(f"unsupported VBN seed version={version:04X} mode={mode}")
        descriptor = (
            validation_fields
            + self.KEY8_ALTERNATIVES[selector["index"]]
            + self.VERSION_KEYS[version]
            + self.MODE_KEYS[mode]
        )
        selector.update({"version": version, "mode": mode})
        return selector, descriptor

    def calculate(self) -> dict:
        message = self.build_message()
        expected = self.compared_value()
        selector, selected_descriptor = self.selected_descriptor()
        selected_hmac = hmac.new(selected_descriptor, message, hashlib.sha256).digest()
        trials = []
        match = None
        for index, descriptor in self.descriptor_candidates():
            actual = hmac.new(descriptor, message, hashlib.sha256).digest()
            trials.append({"selector_qword_index": index,
                           "descriptor": descriptor.hex().upper(),
                           "actual": actual.hex().upper()})
            if actual == expected:
                match = trials[-1]
        return {
            "source": str(self.dump.path),
            "source_sha256": hashlib.sha256(self.dump.path.read_bytes()).hexdigest(),
            "algorithm": "LoSha256HmacMessageDigest (LIC algorithm 0x0E)",
            "key_initialization": (
                "category-7 factory -> method +0x08(descriptor) -> intermediate "
                "handle -> category-2 method +0x10. In RS_750-J, provider IDs 1 "
                "and 4 converge on CRCSPMACHINE. It copies the descriptor verbatim "
                "into CRKey; CLIC command 0x3D implements standard HMAC framing. "
                "Exact descriptor/message parity is proven for samples whose "
                "independent HMAC equals the directly stored VBN; a mismatch is "
                "fail-closed as an unrecovered canonical/runtime variant"
            ),
            "message_length": len(message),
            "message_sha256": hashlib.sha256(message).hexdigest(),
            "aggregate_physical_entry_count": 1 + sum(
                chunk.aggregate_delivery == "RETAINED_SOURCE_POINTER"
                for chunk in self.chunks
            ),
            "aggregate_order": (
                "one C78957B4 owned copied-byte stream, followed by C7895974 "
                "retained source-pointer spans in append order"
            ),
            "segment_bases": [f"{value:016X}" for value in self.segment_bases],
            "live_compared_value": expected.hex().upper(),
            "live_compared_value_confidence": "CONFIRMED_LIVE_STRUCTURE",
            "independently_calculated_value": (
                selected_hmac.hex().upper() if selected_hmac == expected else None
            ),
            # Deprecated compatibility key.  Retained so old notebooks do not
            # break, but explicitly classified above and in the CLI output.
            "expected": expected.hex().upper(),
            "descriptor_selector": selector,
            "selected_descriptor": selected_descriptor.hex().upper(),
            "selected_descriptor_hmac_sha256": selected_hmac.hex().upper(),
            "selected_descriptor_hmac_matches": selected_hmac == expected,
            "raw_descriptor_key_match": match,
            "descriptor_hmac_trials": trials,
            # Compatibility name retained for existing consumers.  These are
            # rejected as complete PVV results, not proof that no provider can
            # use the descriptor bytes as its key input.
            "rejected_raw_descriptor_key_trials": trials,
            "chunks": self._chunk_manifest(),
        }

    def _chunk_manifest(self) -> list[dict[str, object]]:
        result: list[dict[str, object]] = []
        append_offsets: dict[int, int] = {}
        append_offset = 0
        for chunk in self.chunks:
            append_offsets[id(chunk)] = append_offset
            append_offset += len(chunk.data)

        physical_offsets: dict[int, int] = {}
        aggregate_entries: dict[int, int] = {}
        message_offset = 0
        retained_entry = 1
        for chunk in self.aggregate_ordered_chunks():
            physical_offsets[id(chunk)] = message_offset
            if chunk.aggregate_delivery == "COPIED_INTO_AGGREGATE_STORAGE":
                aggregate_entries[id(chunk)] = 0
            else:
                aggregate_entries[id(chunk)] = retained_entry
                retained_entry += 1
            message_offset += len(chunk.data)

        for index, chunk in enumerate(self.chunks):
            length = len(chunk.data)
            result.append({
                "index": index,
                "label": chunk.label,
                "append_call_offset": append_offsets[id(chunk)],
                "message_offset": physical_offsets[id(chunk)],
                "aggregate_entry_ordinal": aggregate_entries[id(chunk)],
                "length": length,
                "source_pointer": (
                    f"0x{chunk.source_pointer:016X}"
                    if chunk.source_pointer is not None else None
                ),
                "construction": chunk.construction,
                "aggregate_delivery": chunk.aggregate_delivery,
                "transformed_offsets": list(chunk.transformed_offsets),
                "sha256": hashlib.sha256(chunk.data).hexdigest(),
            })
        return result


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Calculate PVV inputs from a retained IBM DAD program dump."
    )
    parser.add_argument("dump", type=Path, metavar="DAD_DUMP")
    parser.add_argument(
        "--json",
        action="store_true",
        help="write the complete calculation record as JSON",
    )
    args = parser.parse_args()
    result = V7R5ProgramValidation(DADProgramDump(args.dump)).calculate()
    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print(f"source={result['source']}")
        print(f"algorithm={result['algorithm']}")
        print(f"message_length={result['message_length']}")
        print(f"stored_pvv={result['live_compared_value']}")
        print(f"descriptor_selector_index={result['descriptor_selector']['index']}")
        print(f"selected_descriptor={result['selected_descriptor']}")
        print(f"calculated_pvv={result['selected_descriptor_hmac_sha256']}")
        status = (
            "PVV_MATCH"
            if result["selected_descriptor_hmac_matches"]
            else "PVV_MISMATCH"
        )
        print(f"status={status}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (DumpError, OSError, ValueError, struct.error) as error:
        print(f"Error: {error}", file=sys.stderr)
        raise SystemExit(2)
