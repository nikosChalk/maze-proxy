

from pwnlib.util.fiddling import hexdump

def indented_hexdump(data, indent_level=0):
    s = hexdump(data, groupsize=8, width=24)
    if indent_level > 0:
        lines = s.split('\n')
        lines = [' '*indent_level + l for l in lines]
        s = '\n'.join(lines)
    return s
