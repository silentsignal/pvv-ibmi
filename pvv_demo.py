#!/usr/bin/env python3
"""Check and repair PVV values in supported IBM i 7.5 save files.

This is the public command-line entry point for the pvv-ibmi tools.  It joins
the reconstructed program-validation calculation with the independent SAVF
checksum implementation and always writes repairs to a separate file.
"""

from __future__ import annotations

import argparse
import hashlib
import struct
import sys
from dataclasses import dataclass
from pathlib import Path

import savf_checksum_demo as savf
from scripts.reconstruct_v7r5_pvv import DumpError, V7R5ProgramValidation


PROGRAM_TYPES = {
    0x01F0: "*PGM",
    0x0201: "*PGM",
    0x0203: "*SRVPGM",
}


class PVVError(RuntimeError):
    """Raised when a save file falls outside the supported PVV format."""

    pass


@dataclass(frozen=True)
class Section:
    index: int
    base: int
    capacity: int
    length: int
    section_type: int
    section_subtype: int
    item_offset: int
    logical_offset: int

    @property
    def end(self) -> int:
        return self.base + self.length


@dataclass(frozen=True)
class Program:
    name: str
    object_type: str
    item_offset: int
    release: int
    sections: tuple[Section, ...]


@dataclass(frozen=True)
class Result:
    program: Program
    stored: bytes
    calculated: bytes
    message_length: int
    message_sha256: str
    field_addresses: tuple[int, ...]

    @property
    def valid(self) -> bool:
        return self.stored == self.calculated


class ProgramSpace:
    """Sparse saved-program address space backed by the logical SAVF stream."""

    def __init__(self, path: Path, logical: bytes, program: Program):
        self.path = path
        self.logical = logical
        self.program = program
        self.segments = program.sections
        # V7R5ProgramValidation discovers the base segment through this map.
        # DADProgramDump exposes the same small interface for retained dumps.
        self.lines = {(section.base >> 24, 0): b"" for section in self.segments}

    @staticmethod
    def pointer(segment: int, offset: int) -> int:
        if segment >= 1 << 40 or offset >= 1 << 24:
            raise PVVError("program address is outside the supported format")
        return segment << 24 | offset

    def locate(self, pointer: int, length: int = 1) -> tuple[Section, int]:
        if length < 0:
            raise PVVError("read length cannot be negative")
        matches = [
            section
            for section in self.segments
            if pointer >= section.base and pointer + length <= section.end
        ]
        if len(matches) != 1:
            raise PVVError(
                f"program address 0x{pointer:016X} with length 0x{length:X} is not mapped"
            )
        section = matches[0]
        return section, pointer - section.base

    def read(self, pointer: int, length: int) -> bytes:
        section, relative = self.locate(pointer, length)
        start = section.logical_offset + relative
        value = self.logical[start:start + length]
        if len(value) != length:
            raise PVVError("program data is truncated")
        return value

    def u16(self, pointer: int) -> int:
        return int.from_bytes(self.read(pointer, 2), "big")

    def u32(self, pointer: int) -> int:
        return int.from_bytes(self.read(pointer, 4), "big")

    def u64(self, pointer: int) -> int:
        return int.from_bytes(self.read(pointer, 8), "big")

    def logical_location(self, pointer: int, length: int) -> int:
        section, relative = self.locate(pointer, length)
        return section.logical_offset + relative


def u16(data: bytes, offset: int) -> int:
    return int.from_bytes(data[offset:offset + 2], "big")


def u32(data: bytes, offset: int) -> int:
    return int.from_bytes(data[offset:offset + 4], "big")


def u64(data: bytes, offset: int) -> int:
    return int.from_bytes(data[offset:offset + 8], "big")


def parse_programs(logical: bytes) -> tuple[Program, ...]:
    """Return supported program objects found in an uncompressed SAVF."""

    programs: list[Program] = []
    for item in savf.parse_uncompressed_items(logical):
        object_type = PROGRAM_TYPES.get(item.item_type)
        if object_type is None:
            continue
        header = logical[item.offset:item.offset + savf.PAYLOAD_SIZE]
        release = u16(header, 0x50)
        section_count = u32(header, 0x64)
        if release <= 32:
            raise PVVError(f"{item.name}: old section descriptors are not supported")
        if section_count == 0:
            raise PVVError(f"{item.name}: program has no saved sections")
        descriptor_pointer = u64(header, 0x108)
        type_pointer = u64(header, 0x140)
        if descriptor_pointer == 0:
            raise PVVError(f"{item.name}: section descriptor pointer is absent")
        descriptor_offset = (descriptor_pointer & 0x00FFFFFF) - 0x1000
        type_offset = (type_pointer & 0x00FFFFFF) - 0x1000 if type_pointer else None
        section_base = ((item.header_occupation // 4096) + 1) * 4096
        if descriptor_offset < 0 or descriptor_offset + section_count * 16 > section_base:
            raise PVVError(f"{item.name}: section descriptor table is outside the header")
        if type_offset is not None and (
            type_offset < 0 or type_offset + section_count * 8 > section_base
        ):
            raise PVVError(f"{item.name}: section type table is outside the header")
        sections = []
        data_offset = section_base
        ranges = []
        for index in range(section_count):
            descriptor = item.offset + descriptor_offset + index * 16
            capacity, length, base = struct.unpack_from(">IIQ", logical, descriptor)
            if length > capacity:
                raise PVVError(f"{item.name}: section {index} is longer than its capacity")
            if base == 0 or base & 0xFFFFFF:
                raise PVVError(f"{item.name}: section {index} has an invalid base address")
            section_type = 0
            section_subtype = 0
            if type_offset is not None:
                type_entry = item.offset + type_offset + index * 8
                section_type, section_subtype = struct.unpack_from(">HH", logical, type_entry)
            interval = (base, base + length)
            if any(interval[0] < end and start < interval[1] for start, end in ranges):
                raise PVVError(f"{item.name}: saved program sections overlap")
            ranges.append(interval)
            sections.append(
                Section(
                    index=index,
                    base=base,
                    capacity=capacity,
                    length=length,
                    section_type=section_type,
                    section_subtype=section_subtype,
                    item_offset=data_offset,
                    logical_offset=item.offset + data_offset,
                )
            )
            data_offset += capacity
        if data_offset > item.length:
            raise PVVError(f"{item.name}: saved sections extend beyond the item")
        programs.append(
            Program(
                name=item.name,
                object_type=object_type,
                item_offset=item.offset,
                release=release,
                sections=tuple(sections),
            )
        )
    if not programs:
        raise PVVError("no supported saved program was found")
    return tuple(programs)


def inspect(path: Path, physical: bytes) -> tuple[Result, ...]:
    """Calculate stored and expected PVVs for every supported program."""

    logical = savf.logical_stream(physical, restore_backup=True)
    results = []
    for program in parse_programs(logical):
        space = ProgramSpace(path, logical, program)
        validation = V7R5ProgramValidation(space)
        message = validation.build_message()
        calculation = validation.calculate()
        calculated = bytes.fromhex(calculation["selected_descriptor_hmac_sha256"])
        addresses = tuple(address for _, address in validation.compared_field_addresses())
        results.append(
            Result(
                program=program,
                stored=validation.compared_value(),
                calculated=calculated,
                message_length=len(message),
                message_sha256=hashlib.sha256(message).hexdigest(),
                field_addresses=addresses,
            )
        )
    return tuple(results)


def write_logical(physical: bytearray, offset: int, value: bytes) -> None:
    cursor = 0
    while cursor < len(value):
        logical_offset = offset + cursor
        record = logical_offset // savf.PAYLOAD_SIZE
        inside = logical_offset % savf.PAYLOAD_SIZE
        count = min(len(value) - cursor, savf.PAYLOAD_SIZE - inside)
        physical_offset = record * savf.PHYSICAL_RECORD_SIZE + inside
        physical[physical_offset:physical_offset + count] = value[cursor:cursor + count]
        cursor += count


def check_container(physical: bytes, table: bytes) -> tuple[bool, str, str, int]:
    invalid, stored, calculated = savf.validate_file(physical, table)
    return not invalid and stored == calculated, stored.hex(), calculated.hex(), len(invalid)


def show(path: Path, physical: bytes, table: bytes) -> bool:
    """Print a verification report and return true when every check passes."""

    container_valid, stored_global, calculated_global, invalid_records = check_container(
        physical, table
    )
    print(f"File: {path}")
    record_status = "valid" if invalid_records == 0 else f"{invalid_records} invalid"
    print(f"SAVF record checks: {record_status}")
    print(f"SAVF stored global: {stored_global}")
    print(f"SAVF calculated global: {calculated_global}")
    print(f"SAVF checks: {'valid' if container_valid else 'invalid'}")
    results = inspect(path, physical)
    for result in results:
        print()
        print(f"Object: {result.program.name} {result.program.object_type}")
        print(f"Stored PVV: {result.stored.hex()}")
        print(f"Calculated PVV: {result.calculated.hex()}")
        print(f"Canonical message bytes: {result.message_length}")
        print(f"Canonical message SHA256: {result.message_sha256}")
        print(f"PVV: {'valid' if result.valid else 'invalid'}")
    return container_valid and all(result.valid for result in results)


def fix(source: Path, output: Path, table: bytes) -> tuple[int, int]:
    """Repair PVV and SAVF checks in a newly written output file."""

    if source.resolve() == output.resolve():
        raise PVVError("input and output paths must differ")
    original = source.read_bytes()
    results = inspect(source, original)
    changed_fields = 0
    modified = bytearray(original)
    logical = savf.logical_stream(original, restore_backup=True)
    programs = {program.name: program for program in parse_programs(logical)}
    for result in results:
        if result.valid:
            continue
        program = programs[result.program.name]
        space = ProgramSpace(source, logical, program)
        for index, address in enumerate(result.field_addresses):
            value = result.calculated[index * 8:(index + 1) * 8]
            if space.read(address, 8) != value:
                write_logical(modified, space.logical_location(address, 8), value)
                changed_fields += 1
    repaired = savf.repair(bytes(modified), table)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_bytes(repaired)
    if not show(output, repaired, table):
        output.unlink(missing_ok=True)
        raise PVVError("verification failed and the output was removed")
    return changed_fields, sum(a != b for a, b in zip(original, repaired))


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Check and repair PVV values in supported IBM i 7.5 SAVFs."
    )
    parser.add_argument(
        "--table",
        type=Path,
        default=Path("sandbox.ser"),
        metavar="PATH",
        help="sandbox.ser extracted from jSAVF (default: ./sandbox.ser)",
    )
    commands = parser.add_subparsers(dest="command", required=True)
    check_parser = commands.add_parser(
        "check",
        help="verify SAVF checks and calculate stored program PVVs",
    )
    check_parser.add_argument("savf", type=Path, metavar="SAVF")
    fix_parser = commands.add_parser(
        "fix",
        help="write a repaired copy and verify it",
    )
    fix_parser.add_argument("source", type=Path, metavar="INPUT")
    fix_parser.add_argument("output", type=Path, metavar="OUTPUT")
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    table = savf.load_table(args.table)
    if args.command == "check":
        data = args.savf.read_bytes()
        return 0 if show(args.savf, data, table) else 1
    changed_fields, changed_bytes = fix(args.source, args.output, table)
    print()
    print(f"PVV fields changed: {changed_fields}")
    print(f"Physical bytes changed: {changed_bytes}")
    print(f"Output: {args.output}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (DumpError, PVVError, OSError, ValueError, struct.error) as error:
        print(f"Error: {error}", file=sys.stderr)
        raise SystemExit(2)
