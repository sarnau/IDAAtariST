# Atari ST scripts for IDA Starter/Pro from Hex-Rays

As a start a simple loader for Atari ST Gemdos programs.

# Installation

To install: place this python script inside the `loaders` directory
of IDA. Tested with IDA Pro 7.2 in macOS, but it should work on any
platform. On macOS/Linux you can simply copy the `loaders` directory
to `~/.idapro`. If the directory already exists, just copy the script into
it.

# Usage

Open an Atari Gemdos file in IDA, if the file header matches, it will
automatically detect it and creates TEXT/DATA/BSS segments, load the data,
relocates the application and even applies a symbol table, if it exists
within the file.

The GST extended DRI symbol format is also supported, so
up to 14 character long symbols do work. Currently only global symbols are
supported, not local ones or register based ones.
