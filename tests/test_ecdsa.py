from src.crypto.ecdsa import Signature


def test_generation_and_verification() -> None:
    generated = Signature.generate_many(1000)
    checks = Signature.verify_all(generated)
    assert checks
