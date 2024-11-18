#!/usr/bin/env python
import struct
import jinja2
import re
from math import ceil

def generate_test(input_text: str) -> str:
    matches = re.findall(r"Vector (\d+)\nKey1 ([0-9a-fA-F]+)\nKey2 ([0-9a-fA-F]+)\nData .nit .equence .umber ([0-9a-fA-F]+)\n((PTX [0-9a-fA-F]+\n)+)((TWK [0-9a-fA-F]+\n)*)((CTX [0-9a-fA-F]+\n)+)", input_text)

    test_cases = [ \
        { \
            "key": format_bytes(bytes.fromhex(m[1]) + bytes.fromhex(m[2])), \
            "vectorNum": m[0], \
            "sector": hex(get_big_endian(m[3])), \
            "expectedPlaintext": format_bytes(parse_multiline_hex(m[4])), \
            "expectedCiphertext": format_bytes(parse_multiline_hex(m[8])), \
        } for m in matches \
    ]

    templateLoader = jinja2.FileSystemLoader(searchpath="./")
    templateEnv = jinja2.Environment(loader=templateLoader)
    TEMPLATE_FILE = "template.cs"
    template = templateEnv.get_template(TEMPLATE_FILE)

    return template.render(test_cases=test_cases)

def get_big_endian(data: str) -> int:
    data = bytes.fromhex(data.rjust(2, '0'))
    data = data.ljust(8, b'\0')

    return struct.unpack("<Q", data)[0]

def parse_multiline_hex(input: str) -> bytes:
    input = input.replace("PTX ", "").replace("CTX ", "").replace(",\n","")
    return bytes.fromhex(input)

def format_bytes(input: bytes) -> str:
    padding = " " * 12
    input_bytes = ["0x%02x" % i for i in input]
    input_bytes = chunk(input_bytes, 8)
    
    input_bytes = [", ".join(b) for b in input_bytes]
    return (",\n" + padding).join(input_bytes)

def chunk(lst, size: int):
  return list(
    map(lambda x: lst[x * size:x * size + size],
      list(range(ceil(len(lst) / size)))))

if __name__ == "__main__":
    text = ""
    with open("./test_case_input.txt") as f:
        text = f.read()
    
    text = generate_test(text)

    with open("../tests/IeeeVectorsTests.cs", "w") as f:
        f.write(text)
