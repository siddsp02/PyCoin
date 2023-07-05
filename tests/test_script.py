from src.script import run, stack


def test_run() -> None:
    # Basic arithmetic operations.
    # Addition.
    assert run("2 7 OP_ADD") == 9
    assert run("4 9 OP_ADD") == 13
    assert run("1 2 OP_ADD 2 OP_ADD") == 5
    # Subtraction.
    assert run("10 5 OP_SUB") == 5
    # Equality.
    # Check that a boolean is returned and not just a non-zero value.
    assert run("4 5 OP_EQUAL") == False
    assert run("5 5 OP_EQUAL") == True
    assert run("5 5 OP_ADD 10 OP_EQUAL") == True
