from src.script import OPCODE_MAP, stack


def test_basic_ops_with_stack() -> None:
    stack.append(3)
    stack.append(4)
    OPCODE_MAP["OP_ADD"]()
    assert stack.pop() == 7
    stack.append(5)
    stack.append(10)
    OPCODE_MAP["OP_SUB"]()
    assert stack.pop() == 5
