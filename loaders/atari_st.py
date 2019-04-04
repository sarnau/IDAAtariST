# a simple loader for Atari ST gemdos programs
# It detects the file header, creates TEXT/DATA/BSS segments,
# loads the data, relocates the addresses and even applies a symbol table,
# if it exists within the file

# To install: place this python script inside the 'loaders' directory
# of IDA. Tested with IDA Pro 7.2 in macOS, but it should work on any
# platform.

# 2019 Markus Fritze, <https://github.com/sarnau/IDAAtariST>

import idaapi
import ida_idp
import ida_bytes
import idc
import struct
import ctypes

uint8  = ctypes.c_ubyte
char   = ctypes.c_char
uint32 = ctypes.c_uint
uint64 = ctypes.c_uint64
uint16 = ctypes.c_ushort
ushort = uint16

# Atari ST Pexec() header
class gemdos_executable_header(ctypes.BigEndianStructure):
    _pack_ = 1
    _fields_ = [
        ("PRG_magic", uint16), # This WORD contains the magic value (0x601A).
        ("PRG_tsize", uint32), # This LONG contains the size of the TEXT segment in bytes.
        ("PRG_dsize", uint32), # This LONG contains the size of the DATA segment in bytes.
        ("PRG_bsize", uint32), # This LONG contains the size of the BSS segment in bytes.
        ("PRG_ssize", uint32), # This LONG contains the size of the symbol table in bytes.
        ("PRG_res1",  uint32), # This LONG is unused and is currently reserved.
        ("PRGFLAGS",  uint32), # This LONG contains flags which define certain process characteristics (as defined below).
        ("ABSFLAG",   uint16), # This WORD flag should be non-zero to indicate that the program has no fixups or
                                 # 0 to indicate it does. Since some versions of TOS handle files with this value
                                 # being non-zero incorrectly, it is better to represent a program having no fixups
                                 # with 0 here and placing a 0 longword as the fixup offset.
    ]

# PRGFLAGS
# PF_FASTLOAD	 0   If set, clear only the BSS area on program load, otherwise clear the entire heap
# PF_TTRAMLOAD	 1   If set, the program may be loaded into alternative RAM, otherwise it must be loaded into standard RAM.
# PF_TTRAMMEM	 2   If set, the program's Malloc() requests may be satisfied from alternative RAM, otherwise they must be satisfied from standard RAM.

AtariSTBaseAddress = 0x10000 # the application is loaded to this address
AtariSTProgramName = "Atari ST Program"

# -----------------------------------------------------------------------

def read_struct(li, struct):
    s = struct()
    slen = ctypes.sizeof(s)
    bytes = li.read(slen)
    fit = min(len(bytes), slen)
    ctypes.memmove(ctypes.addressof(s), bytes, fit)
    return s

# -----------------------------------------------------------------------
def accept_file(li, filename):
    """
    Check if the file is of supported format

    @param li: a file-like object which can be used to access the input data
    @param filename: name of the file, if it is an archive member name then the actual file doesn't exist
    @return: 0 - no more supported formats
             string "name" - format name to display in the chooser dialog
             dictionary { 'format': "name", 'options': integer }
               options: should be 1, possibly ORed with ACCEPT_FIRST (0x8000)
               to indicate preferred format
    """

    li.seek(0)
    header = read_struct(li, gemdos_executable_header)
    if header.PRG_magic == 0x601A:
        return {'format': AtariSTProgramName, 'processor': '68K'}

    # unrecognized format
    return 0

# -----------------------------------------------------------------------
def load_file(li, neflags, format):

    """
    Load the file into database

    @param li: a file-like object which can be used to access the input data
    @param neflags: options selected by the user, see loader.hpp
    @return: 0-failure, 1-ok
    """

    if format == AtariSTProgramName:
        idaapi.set_processor_type('68K', ida_idp.SETPROC_LOADER)

        li.seek(0)
        header = read_struct(li, gemdos_executable_header)

        base_addr = AtariSTBaseAddress

        text_addr = base_addr
        data_addr = text_addr + header.PRG_tsize
        bss_addr = data_addr + header.PRG_dsize
        idc.add_segm_ex(text_addr, text_addr+header.PRG_tsize, 0, 1, idaapi.saRelPara, idaapi.scPub, idc.ADDSEG_NOSREG)
        idc.set_segm_name(text_addr, 'tseg')
        idc.add_segm_ex(data_addr, data_addr+header.PRG_dsize, 0, 1, idaapi.saRelPara, idaapi.scPub, idc.ADDSEG_NOSREG)
        idc.set_segm_name(data_addr, 'dseg')
        idc.add_segm_ex(bss_addr, bss_addr+header.PRG_bsize, 0, 1, idaapi.saRelPara, idaapi.scPub, idc.ADDSEG_SPARSE)
        idc.set_segm_name(bss_addr, 'bseg')
        li.file2base(ctypes.sizeof(gemdos_executable_header), text_addr, text_addr + header.PRG_tsize + header.PRG_dsize, 0)

        # relocate the application
        li.seek(0, idaapi.SEEK_END)
        filesize = li.tell()
        li.seek(0, idaapi.SEEK_SET)
        relocDataOffset = ctypes.sizeof(gemdos_executable_header) + header.PRG_tsize + header.PRG_dsize + header.PRG_ssize
        li.seek(relocDataOffset)
        relocData = li.read(filesize - relocDataOffset)
        roffset = 4
        rea = struct.unpack('>I', relocData[:roffset])[0]
        if rea != 0:
            rea = rea + base_addr
            idc.patch_dword(rea, ida_bytes.get_dword(rea) + base_addr)
            if rea >= data_addr: # in the DATA segment, make sure it is an actual pointer
                idc.create_dword(rea)
            while True:
                offset = ord(relocData[roffset])
                roffset += 1
                if offset == 0: # end of the relocation table
                    break
                if offset == 1: # odd numbers are not valid, 1 is a special case to skip 254 bytes without relocating
                    rea += 254
                    continue
                rea += offset
                idc.patch_dword(rea, ida_bytes.get_dword(rea) + base_addr)
                if rea >= data_addr: # in the DATA segment, make sure it is an actual pointer
                    idc.create_dword(rea)

        # apply a symbol table, if part of the file
        if header.PRG_ssize:
            symboltableDataOffset = ctypes.sizeof(gemdos_executable_header) + header.PRG_tsize + header.PRG_dsize
            li.seek(symboltableDataOffset)
            symboltableData = li.read(header.PRG_ssize)
            soffset = 0
            while soffset < header.PRG_ssize:
                entry = symboltableData[soffset:soffset+14]
                soffset += 14
                name = entry[:8]
                flags,value = struct.unpack('>HL', entry[8:])
                if (flags & 0x0048) and soffset + 14 < header.PRG_ssize: # GST extended DRI symbol format?
                    entry = symboltableData[soffset:soffset+14]
                    soffset += 14
                    name += entry[:8]
                if (flags & 0xf000)==0xa000: # global defined symbol? (registers, etc are not supported)
                    value += text_addr # relocate the value
                    if (flags & 0xf00) == 0x0100: # BSS
                        idc.set_name(value,	name);
                    elif (flags & 0xf00) == 0x0200: # TEXT
                        idaapi.add_entry(value, value, name, 1)
                    elif (flags & 0xf00) == 0x0400: # DATA
                        idc.set_name(value,	name);

        idaapi.add_entry(text_addr, text_addr, "start", 1)
        idaapi.plan_and_wait(text_addr, text_addr + header.PRG_tsize);
        idaapi.auto_wait();
        return 1

    return 0
