from src.ecdsa import decode, encode


def test_der_signature_encode() -> None:
    sig = (
        0xED81FF192E75A3FD2304004DCADB746FA5E24C5031CCFCF21320B0277457C98F,
        0x7A986D955C6E0CB35D446A89D3F56100F4D7F67801C31967743A9C8E10615BED,
    )
    sig_der = encode(sig)
    assert (
        sig_der.hex()
        == "3045022100ed81ff192e75a3fd2304004dcadb746fa5e24c5031ccfcf21320b0277457c98f02207a986d955c6e0cb35d446a89d3f56100f4d7f67801c31967743a9c8e10615bed"
    )


def test_der_signature_decode() -> None:
    sig = decode(
        bytes.fromhex(
            "3045022100ed81ff192e75a3fd2304004dcadb746fa5e24c5031ccfcf21320b0277457c98f02207a986d955c6e0cb35d446a89d3f56100f4d7f67801c31967743a9c8e10615bed"
        )
    )
    r, s = sig
    assert (r, s) == (
        0xED81FF192E75A3FD2304004DCADB746FA5E24C5031CCFCF21320B0277457C98F,
        0x7A986D955C6E0CB35D446A89D3F56100F4D7F67801C31967743A9C8E10615BED,
    )
