# pvv-ibmi

`pvv-ibmi` checks and repairs the Program Validation Value (PVV) stored with
supported IBM i 7.5 programs in a save file (SAVF).

The implementation accompanies the Silent Signal research into how IBM i
constructs PVV. It rebuilds the protected program message, derives the 32-byte
descriptor, calculates HMAC-SHA-256, and compares the result with the four
stored PVV fragments. When asked to repair a save file, it also recalculates
the independent SAVF record and global checksums.

The input file is never modified. Repairs are written to the output path given
on the command line.

## Supported input

The current implementation supports uncompressed IBM i 7.5 `*PGM` and
`*SRVPGM` objects that use the saved-program layout recovered in the research.
It deliberately stops on unknown program versions, section layouts, pointer
formats, and validation routes instead of guessing.

A valid PVV is a consistency result. It is not a digital signature, does not
grant restore authority, and does not override IBM i restore policy.

## Requirements

- Python 3.10 or later
- `sandbox.ser` from the jSAVF 1.83 distribution

The checksum code validates the lookup table before using it. One way to
extract the resource is:

```sh
curl -fL -A 'Mozilla/5.0' -O \
  https://www.anerty.net/dl/jsavf-dist-1.83-jars-only-linux.tar.xz
tar -xf jsavf-dist-1.83-jars-only-linux.tar.xz
unzip -p jsavf/jSAVF-1.83.jar \
  net/anerty/os400/savf/check/sandbox.ser > sandbox.ser
```

Run the commands below from the repository directory. The project uses only
the Python standard library.

## Check a save file

```sh
python3 pvv_demo.py --table sandbox.ser check input.FILE
```

For every supported program, the report includes:

- SAVF record-check and global-checksum status;
- stored and calculated PVV;
- canonical-message length and SHA-256; and
- the final PVV result.

`check` returns status 0 when the SAVF checks and every supported PVV are
valid, status 1 when verification completes but a value is invalid, and status
2 for an input, format, or I/O error.

## Repair a save file

```sh
python3 pvv_demo.py --table sandbox.ser \
  fix modified.FILE repaired.FILE
```

`fix` calculates the expected PVV, updates only differing PVV fragments,
repairs the SAVF checksums, writes the requested output file, and reopens that
file for verification before reporting success. The input and output paths
must be different.

The command reports how many PVV fields and physical SAVF bytes changed. A
valid input is a useful no-op control: its repaired output should be
byte-for-byte identical to the input.

Use disposable laboratory objects and keep an untouched copy of every SAVF.
Restoring an object remains subject to the target system's authority and
restore-policy requirements.

## Repository layout

- `pvv_demo.py` is the supported command-line interface. It finds program
  objects, reports stored and calculated PVVs, and coordinates repair.
- `scripts/reconstruct_v7r5_pvv.py` contains the recovered graph walk,
  pointer canonicalization, message ordering, descriptor selection, and
  HMAC-SHA-256 calculation. It can also inspect a retained IBM DAD program
  dump directly.
- `savf_checksum_demo.py` implements the separate SAVF record and global
  checksum layers. Its standalone CLI retains the checksum-repair and QSYS
  catalogue editing commands used in the earlier SAVF research.

For normal PVV work, use `pvv_demo.py`; the other entry points expose the
lower layers for research and testing.

## Research

The SAVF checksum implementation is described separately:

[512 bytes at a time: reconstructing IBM i save-file checksums](https://blog.silentsignal.eu/2026/10/06/512-bytes-at-a-time-reconstructing-IBM-i-save-file-checksums/)
