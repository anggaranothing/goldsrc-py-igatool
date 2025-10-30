'''
goldsrc-py-igatool
Copyright 2025 Anggaranothing

This program is free software:
you can redistribute it and/or modify it under the terms of the GNU Lesser General Public License as published by the Free Software Foundation,
either version 3 of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
See the GNU Lesser General Public License for more details.

You should have received a copy of the GNU Lesser General Public License along with this program.
If not, see <https://www.gnu.org/licenses/>.
'''

__VERSION__ = '0.2.0'
__AUTHOR__ = 'AnggaraNothing'
import sys
from io import (
    SEEK_SET,
    SEEK_END,
    BytesIO,
)
from pathlib import (
    Path,
)
from ICECipher import (
    IceKey,
)



def alloc_len (aligment: int, size: int):
    return aligment * ((size + aligment - 1) // aligment)


class CPPRandom:
    def __init__ (self):
        self.seed(1)
    
    def seed (self, seed: int):
        self._seed = seed

    def rand (self):
        self._seed = 0x343FD * self._seed + 0x269EC3
        return (self._seed >> 16) & 0x7FFF


def _genkey (pwd: bytes):
    if not pwd:
        raise ValueError('Bogus or empty password')
    pwd_len = len(pwd)
    if pwd_len < 4:
        raise ValueError('Password too short, must be at least 4 bytes')
    pwd_view = memoryview(pwd)
    trunc_len = (pwd_len + 3) & 0xfffffffc
    trunc = bytearray(trunc_len)
    trunc_view = memoryview(trunc)
    copy_len = trunc_len if trunc_len < pwd_len else pwd_len
    trunc_view[:copy_len] = pwd_view[:copy_len]
    key_seed = 0
    for _ in range(pwd_len, 0, -4):
        key_seed = key_seed ^ int.from_bytes(trunc_view[:4], 'little')
        trunc_view = trunc_view[4:]
    key_gen = CPPRandom()
    key_gen.seed(key_seed)
    result = bytearray(32)
    for i in range(4):
        for j in range(8):
            v6 = key_gen.rand() & 0xFF
            result[i * 8 + j] = v6
    return result


IGA_KEY = b'\x32\xA6\x21\xE0\xAB\x6B\xF4\x68\x93\x70\xF1\x96\xE0\x38\x75\x2C\xBA\xC6\x07\x86\xFB\xB3\x71\xF4\xE3\x9B\x13\x22\x0C\xFE\x88\x3A'
def _cipher (data: bytes, is_encrypt: bool=True):
    result = None
    if not data:
        return result
    data_view = memoryview(data)
    if is_encrypt:
        data_size = len(data)
        result = bytearray(alloc_len(8, 4 + data_size))
        result[:4] = data_size.to_bytes(4, 'little')
        result[4:data_size] = data
        data_view = memoryview(result)[4:]
        cipher_offset = 4
    else:
        data_size = int.from_bytes(data_view[:4], 'little')
        result = bytearray(data_size)
        data_view = data_view[4:]
        cipher_offset = 0
    cipher = IceKey(4, IGA_KEY)
    cipher_func = cipher.Encrypt if is_encrypt else cipher.Decrypt
    result[cipher_offset:] = cipher_func(data_view)
    result_size = len(result)
    if not is_encrypt and result_size != data_size:
        print(f'WARNING: Expected length {data_size} bytes, got {result_size}')
        result = result[:data_size]
    return result


IGA_WAD_MAGIC = b'\x01\x00\x01\x00'
def _wad (dirpath: str|Path) -> bytes:
    dirpath = Path(dirpath).resolve(True)
    if not dirpath.is_dir():
        return
    entries: dict[Path,tuple[str,int]] = {x: (x.stem, x.stat().st_size) for x in dirpath.glob('*.bmp')}
    if not entries:
        return
    entries_len = len(entries)
    entry_offset = 8 + 72 * entries_len
    result = bytearray(entry_offset + sum(x[1] for x in entries.values()))
    result_view = memoryview(result)
    result_view[:4] = IGA_WAD_MAGIC
    result_view = result_view[4:]
    result_view[:4] = entries_len.to_bytes(4, 'little')
    result_view = result_view[4:]
    for k,v in entries.items():
        entry_name, entry_size = v
        utf8 = entry_name.encode('utf8')
        utf8_len = min(64, len(utf8))
        utf8 = utf8[:utf8_len]
        print(f'BMP name: {utf8!r}')
        result_view[:utf8_len] = utf8
        result_view = result_view[64:]
        result_view[:4] = entry_offset.to_bytes(4, 'little')
        result_view = result_view[4:]
        result_view[:4] = entry_size.to_bytes(4, 'little')
        result_view = result_view[4:]
        entry_offset = entry_offset + entry_size
    for k,v in entries.items():
        _, entry_size = v
        print(f'BMP path: {k.as_posix()}')
        with k.open('rb') as entry_file:
            result_view[:entry_size] = entry_file.read()
            result_view = result_view[entry_size:]
    assert not result_view, "bool(result_view) == False"
    return result


def _unwad (dirpath: str|Path, data: bytes):
    if not data:
        raise ValueError('Empty data')
    data_size = len(data)
    if data_size < 8:
        raise ValueError('Data is too small')
    data_view = memoryview(data)
    entries_view = memoryview(data)
    if entries_view[:4] != IGA_WAD_MAGIC:
        raise ValueError('Invalid magic header')
    entries_view = entries_view[4:]
    entries_len = int.from_bytes(entries_view[:4], 'little')
    entries_view = entries_view[4:4 + entries_len * 72]
    entries: dict[str,bytes] = {}
    for i in range(entries_len):
        entry_name = entries_view[:64].tobytes().decode('utf8').rstrip('\x00')
        entries_view = entries_view[64:]
        entry_offset = int.from_bytes(entries_view[:4], 'little')
        entries_view = entries_view[4:]
        entry_size = int.from_bytes(entries_view[:4], 'little')
        entries_view = entries_view[4:]
        entries[entry_name] = data_view[entry_offset:entry_offset+entry_size]
    assert not entries_view, 'bool(entries_view) == False'
    dirpath = Path(dirpath)
    dirpath.mkdir(parents=True, exist_ok=True)
    dirpath = dirpath.resolve(True)
    for k,v in entries.items():
        bmppath = dirpath / f'{k}.bmp'
        print(f'BMP path: {bmppath.as_posix()}')
        with bmppath.open('wb') as bmpfile:
            bmpfile.write(v)


_HELP = '''usage:  {0} genkey pwd
usage:  {0} e infile outfile
usage:  {0} d infile outfile
usage:  {0} wad inpath outfile
usage:  {0} unwad infile outpath'''

def help ():
    print(_HELP.format(sys.argv[0]))
    sys.exit(-1)


def main (argv: list[str]):
    command = argv[0]
    if command == 'genkey':
        pwd = argv[1]
        key = _genkey(pwd.encode('utf8'))
        for i in range(4):
            for j in range(8):
                print(f'\t{key[i * 8 + j]:03d}, ', end='')
            print('\n', end='')
    else:
        if len(argv) < 3:
            help()
        inpath, outpath = (Path(x) for x in argv[1:])
        cmd = command.lower()[0]
        is_unwad = (cmd == 'u')
        if is_unwad:
            if outpath.is_file():
                help()
        elif outpath.is_dir():
            help()
        print('input_path:', inpath)
        is_encrypt: bool = (cmd == 'e')
        if cmd == 'w':
            is_encrypt = True
            data = _wad(inpath)
            if not data:
                help()
            infile = BytesIO(data)
            outfile = outpath.open('wb')
        else:
            infile = inpath.open('rb')
            if is_unwad:
                outfile = BytesIO()
            else:
                outfile = outpath.open('wb')
        print('output_path:', outpath)
        print('command:', command)
        print('is_encrypt:', is_encrypt)
        outdata = _cipher(infile.read(), is_encrypt)
        infile.close()
        outfile.write(outdata)
        if is_unwad:
            outfile.seek(0, SEEK_SET)
            _unwad(outpath, outfile.getbuffer())
        outfile.close()
    print('done!')


if __name__ == '__main__':
    print(f'igatool {__VERSION__} by {__AUTHOR__}')
    argc = len(sys.argv)
    if argc != 3 and argc != 4:
        help()
    main(sys.argv[1:])
