"""Inspect the shipped PE and embedded icon resources without executing it."""
import hashlib
import io
import json
import pathlib
import struct
import sys
from PIL import Image

path = pathlib.Path(sys.argv[1])
data = path.read_bytes()
pe = struct.unpack_from('<I', data, 60)[0]
assert data[:2] == b'MZ' and data[pe:pe + 4] == b'PE\0\0'
machine, sections = struct.unpack_from('<HH', data, pe + 4)
assert machine == 0x8664, 'Expected Windows x64'
optional_size = struct.unpack_from('<H', data, pe + 20)[0]
optional = pe + 24
assert struct.unpack_from('<H', data, optional)[0] == 0x20B
assert struct.unpack_from('<H', data, optional + 68)[0] == 2, 'Expected GUI subsystem'
section_table = optional + optional_size
mapping = []
for index in range(sections):
    base = section_table + index * 40
    virtual_size, address, raw_size, raw = struct.unpack_from('<IIII', data, base + 8)
    mapping.append((address, max(virtual_size, raw_size), raw))

def offset(rva):
    for address, size, raw in mapping:
        if address <= rva < address + size:
            return raw + rva - address
    raise ValueError(f'Unmapped PE address {rva:x}')

imports_rva = struct.unpack_from('<I', data, optional + 112 + 8)[0]
imports = []
if imports_rva:
    cursor = offset(imports_rva)
    while any(data[cursor:cursor + 20]):
        name = offset(struct.unpack_from('<I', data, cursor + 12)[0])
        imports.append(data[name:data.index(b'\0', name)].decode('ascii'))
        cursor += 20
for name in imports:
    assert not name.lower().startswith(('vcruntime', 'msvcp', 'concrt', 'ucrtbase', 'api-ms-win-crt', 'opengl', 'd3d', 'vulkan')), name

resource_rva = struct.unpack_from('<I', data, optional + 112 + 16)[0]
resource_base = offset(resource_rva)
resources = {}

def directory(relative, names):
    base = resource_base + relative
    named, numbered = struct.unpack_from('<HH', data, base + 12)
    for index in range(named + numbered):
        name, target = struct.unpack_from('<II', data, base + 16 + index * 8)
        if name & 0x80000000:
            text = resource_base + (name & 0x7FFFFFFF)
            size = struct.unpack_from('<H', data, text)[0]
            name = data[text + 2:text + 2 + size * 2].decode('utf-16le')
        if target & 0x80000000:
            directory(target & 0x7FFFFFFF, names + (name,))
        else:
            rva, size = struct.unpack_from('<II', data, resource_base + target)
            resources[names + (name,)] = data[offset(rva):offset(rva) + size]

directory(0, ())
groups = [(key, value) for key, value in resources.items() if key[0] == 14]
assert groups and groups[0][0][1] == 1, 'Expected the application icon in group 1'
group = groups[0][1]
count = struct.unpack_from('<H', group, 4)[0]
headers, pixels = [], []
position = 6 + count * 16
for index in range(count):
    record = group[6 + index * 14:6 + (index + 1) * 14]
    icon_id = struct.unpack_from('<H', record, 12)[0]
    payload = next(value for key, value in resources.items() if key[0] == 3 and key[1] == icon_id)
    headers.append(record[:12] + struct.pack('<I', position))
    pixels.append(payload)
    position += len(payload)
ico = Image.open(io.BytesIO(struct.pack('<HHH', 0, 1, count) + b''.join(headers + pixels)))
source = Image.open('assets/app.ico')
for size in source.ico.sizes():
    actual = ico.ico.getimage(size).convert('RGBA')
    expected = source.ico.getimage(size).convert('RGBA')
    assert actual.tobytes() == expected.tobytes(), size
    bounds = actual.getchannel('A').getbbox()
    assert bounds and bounds[2] - bounds[0] >= size[0] * 0.8, size
print(json.dumps({'file': str(path), 'bytes': len(data), 'sha256': hashlib.sha256(data).hexdigest(), 'machine': 'x64', 'subsystem': 'Windows GUI', 'icon_sizes': sorted(source.ico.sizes()), 'imports': imports}, indent=2))
