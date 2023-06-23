"""
Bitcoin Scripting System (Not Turing Complete).

References: https://en.bitcoin.it/wiki/Script
"""

# Mini scripting language used in the Bitcoin Protocol.
# Consists of enumerated constants as opcodes.
# Many opcodes have been disabled in the current version
# of Bitcoin. This is still very much a WIP since the
# actual functionality has yet to be added.

import inspect
from dataclasses import dataclass
from enum import IntEnum
from itertools import starmap
from operator import add, eq, mul, sub
from pprint import pprint
import re
from typing import Any


stack = []
push = stack.append

# fmt: off

class Opcodes(IntEnum):
    OP_0 = OP_FALSE = 0x00
    OP_PUSHDATA1 = 0x4C
    OP_PUSHDATA2 = 0x4D
    OP_PUSHDATA4 = 0x4E
    OP_1NEGATE = 0x4F
    OP_1 = OP_TRUE = 0x51
    OP_2 = 0x52
    OP_3 = 0x53
    OP_4 = 0x54
    OP_5 = 0x55
    OP_6 = 0x56
    OP_7 = 0x57
    OP_8 = 0x58
    OP_9 = 0x59
    OP_10 = 0x5A
    OP_11 = 0x5B
    OP_14 = 0x5C
    OP_15 = 0x5D
    OP_16 = 0x5E
    OP_NOP = 0x61
    OP_IF = 0x63
    OP_NOTIF = 0x64
    OP_ELSE = 0x67
    OP_ENDIF = 0x68
    OP_VERIFY = 0x69
    OP_RETURN = 0x6A
    OP_TOALTSTACK = 0x6B
    OP_FROMALTSTACK = 0x6C
    OP_IFDUP = 0x73
    OP_DEPTH = 0x74
    OP_DROP = 0x75
    OP_DUP = 0x76
    OP_NIP = 0x77
    OP_OVER = 0x78
    OP_PICK = 0x79
    OP_ROLL = 0x7A
    OP_ROT = 0x7B
    OP_SWAP = 0x7C
    OP_TUCK = 0x7D
    OP_2DROP = 0x6D
    OP_2DUP = 0x6E
    OP_3DUP = 0x6F
    OP_2OVER = 0x70
    OP_2ROT = 0x71
    OP_2SWAP = 0x72
    OP_CAT = 0x7E       # disabled
    OP_SUBSTR = 0x7F    # disabled
    OP_LEFT = 0x80      # disabled
    OP_RIGHT = 0x81     # disabled
    OP_SIZE = 0x82
    OP_INVERT = 0x83    # disabled
    OP_AND = 0x84       # disabled
    OP_OR = 0x85        # disabled
    OP_XOR = 0x86       # disabled
    OP_EQUAL = 0x87
    OP_EQUALVERIFY = 0x88

    # Arithmetic is limited to 32-bit integers with overflow.
    # Scripts abort or fail if any commands are longer than
    # 4 bytes.

    OP_1ADD = 0x8B
    OP_1SUB = 0x8C
    OP_2MUL = 0x8D      # disabled
    OP_2DIV = 0x8E      # disabled
    OP_NEGATE = 0x8F
    OP_ABS = 0x90
    OP_NOT = 0x91
    OP_0NOTEQUAL = 0x92
    OP_ADD = 0x93
    OP_SUB = 0x94
    OP_MUL = 0x95       # disabled
    OP_DIV = 0x96       # disabled
    OP_MOD = 0x97       # disabled
    OP_LSHIFT = 0x98    # disabled
    OP_RSHIFT = 0x99    # disabled
    OP_BOOLAND = 0x9A
    OP_BOOLOR = 0x9B
    OP_NUMEQUAL = 0x9C
    OP_NUMEQUALVERIFY = 0x9D
    OP_NUMNOTEQUAL = 0x9E
    OP_LESSTHAN = 0x9F
    OP_GREATERTHAN = 0xA0
    OP_LESSTHANOREQUAL = 0xA1
    OP_GREATERTHANOREQAL = 0xA2
    OP_MIN = 0xA3
    OP_MAX = 0xA4
    OP_WITHIN = 0xA5
    OP_RIPEMD160 = 0xA6
    OP_SHA1 = 0xA7
    OP_HASH160 = 0xA8
    OP_HASH256 = 0xA9
    OP_CODESEPARATOR = 0xAA
    OP_CHECKSIG = 0xAB
    OP_CHECKSIGVERIFY = 0xAC
    OP_CHECKMULTISIG = 0xAD
    OP_CHECKMULTISIGVERIFY = 0xAF
    OP_CHECKLOCKTIMEVERIFY = 0xB1
    OP_CHECKSEQUENCEVERIFY = 0xB2
    OP_PUBKEYHASH = 0xFD
    OP_PUBKEY = 0xFE
    OP_INVALIDOPCODE = 0xFF
    OP_RESERVED = 0x50
    OP_VER = 0x62
    OP_VERIF = 0x65
    OP_VERNOTIF = 0x66
    OP_RESERVED1 = 0x89
    OP_RESERVED2 = 0x8A
    OP_NOP1 = 0xB0
    OP_NOP4 = 0xB3
    OP_NOP5 = 0xB4
    OP_NOP6 = 0xB5
    OP_NOP7 = 0xB6
    OP_NOP8 = 0xB7
    OP_NOP9 = 0xB8
    OP_NOP10 = 0xB9

# fmt: on


@dataclass
class Opcode:
    name: str
    value: int
    func: Any = None

    def __int__(self) -> int:
        return self.value

    def __eq__(self, other: int) -> bool:
        return int(self) == other

    def __call__(self):
        if self.func is None:
            return None
        args = [stack.pop() for _ in range(self.argcount)]
        result = self.func(*args)
        push(result)

    @property
    def argcount(self) -> int:
        if self.func is None:
            return 0
        return len(inspect.signature(self.func).parameters)


opcode_list = list(starmap(Opcode, Opcodes.__members__.items()))
opcode_map = {opcode.name: opcode for opcode in opcode_list}

opcode_map["OP_ADD"].func = add
opcode_map["OP_SUB"].func = sub
opcode_map["OP_MUL"].func = mul
opcode_map["OP_EQUAL"].func = eq


def run(script: str) -> None:
    split = re.split(r"\s+", script)  # Split by whitespace.
    if not all(s.isnumeric() or s in opcode_map for s in split):
        raise ValueError()
    for item in split:
        if item.isnumeric():
            push(int(item))
        else:
            opcode_map[item]()


if __name__ == "__main__":
    run("2 7 OP_ADD 3 OP_SUB 1 OP_ADD 7 OP_EQUAL")
    print(stack)
