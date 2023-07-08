from typing import NamedTuple

from src.merkle import hash_pair, hash_tree


class BlockTxsAndHash(NamedTuple):
    txs: list[str]
    hash: str


BLOCKS = [
    BlockTxsAndHash(
        txs=[
            "1877fc02dfb78b83b913c0eef8fa5990a55dd4a56449faf97a0dcb6f04cff32b",
            "94d67aa1720ef6b58d130e39f3b7b4e5e7dab07698ab6baf1465e7e639115e05",
            "80a2726fbbe93a8a74bc5a357274510e6a00dfd50489a13c396d2c288e106ec2",
            "5a3e9111cc3a69cc26d290578d46fb40ba1d4abcf706487a1b6d03730d3bdf02",
        ],
        hash="74fe176dcfe07bf6e0ef0f9ee63c81b78623ac9b03137d5f4cfd80f0e500a7c3",
    ),
    BlockTxsAndHash(
        txs=[
            "51d37bdd871c9e1f4d5541be67a6ab625e32028744d7d4609d0c37747b40cd2d",
            "60c25dda8d41f8d3d7d5c6249e2ea1b05a25bf7ae2ad6d904b512b31f997e1a1",
            "01f314cdd8566d3e5dbdd97de2d9fbfbfd6873e916a00d48758282cbb81a45b9",
            "b519286a1040da6ad83c783eb2872659eaf57b1bec088e614776ffe7dc8f6d01",
        ],
        hash="2b12fcf1b09288fcaff797d71e950e71ae42b91e8bdb2304758dfcffc2b620e3",
    ),
    BlockTxsAndHash(
        txs=[
            "5cae61e10768f4af1e99523d041be35f2d9242dd5188957b73de366f7240dd78",
            "ae8ecb842eecceafd5be81f8e408841343eede20d4c490de1ace307a60fa979d",
            "7c530ac3ee35b7c657e7d44f69f99c879e9216019bc0a18e32a78f2a1fab042f",
            "3428ab9ffeb011dd226fa510684cb257e49605f11eae3b98289abbfa97dd7f88",
            "44319a7ff6d1b5a308531d00409dc594b284af9ab193e4b653ea7125d7533d43",
            "19a19fc78601a590a1d9ea7ff0a40afd24bade76bc0e13410761c92d0a4c67a5",
            "27dd73edd20e005227cae0356abac0b485e7691dd16077e17ae85bbcea13bc26",
            "068d305b8808c5acaf1b9b016256d6575721eb3aea84dbe02adaf6a18c05c72e",
            "38542ed74eae494d26a40977e09dad1c14889dc23ec9d9e6ef315ee40eaa4025",
            "bb84ee43d7358392cabf7678cf9565a9dcf03d06e02b157c6537c03268f81054",
            "8526aa88a46b39d2394fe1b47742683bb5bd64d876b19f593a12a92cf1a1e1f5",
            "fd679ffbfd7e7638d3f8a2696c79012dd7a1f3680d1a3b5b4e5cd98c298c27df",
        ],
        hash="39828843d24fff9b7fda6c89c3ce71179f82fe5d882f182a94e5e0c84a152e20",
    ),
    # Test a single transaction.
    BlockTxsAndHash(
        txs=["4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b"],
        hash="4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b",
    ),
    # Test an odd number of transactions.
    BlockTxsAndHash(
        txs=[
            "4a15edc09fa9297b141cf788c69208a4412a71a62967494c081ef629820400ed",
            "fb06570c42a6f9a8096af5789db6282edf26de4c62c1b58fb50dcda727ba8c1a",
            "90bf1722dc39b963d34f9443ed1c4b398238ea534c852d86924855104e7f2eda",
            "cfc7c96f1a5d2c9548b2714a2dc1bd55a12b15fc2e48058eaeb07a831d933838",
            "c2e7161851bfb52e5bc8abc13ee31b697405217e5f7d97d417f7c7f414cefab2",
            "22e931ff3c0798d6426688515bfc637f1cbbd69f811c878d2afa1634d9aed42c",
            "6ac9dba88581de5082290399e79be790f6aed76ecb855c93c7ae08e565034cf6",
            "cd83ea0b64de86da43f5b524f85eb6791f8d96f12d8faa4a2c2f5842b3a2c09a",
            "a4400b103ef41b4b3493ce38d0e7544aa0de044d62ae84712396b31320b19ac1",
            "4a5229bbb2ab7fe1345f8daa8c9d47a8a8e54bbd25259473f04fbd5f6c0261cb",
            "a851d3d80f6db133ea6c901de8050ac9a4c319eece236aa24d6c452c409ba491",
            "f654948272b3e76669307b9719f511fc48b7f9aa45cc49d489c4aca6bab1ec8d",
            "d69c506ed90998b855efd7839d86a60b332ad70ef77cb17b4dcb35160734a5a1",
            "a4526b62320b2809927d395b7238bde9a14475baeea04785c60a3a2adf1d56b0",
            "69044490b8b484dd5e92ab89bfb0a486797d6e0881a5775cac3465afdb58a64a",
            "6cbd43fb5c632692f32005d3d796d56817f948e2dbed29aa26b5a34eb5758cc1",
            "00b051310a776ce65813b6f06285d6d96fac433708faedb4a1fa1a49fb6b1e0b",
            "298092de20edc9b8165b490b322f993e7b0b266789d6534954a96f068c288541",
            "6b87544e34c9bc18bb0f451fdb8291b7d37d4a49642f65d21c48c741d991b6f3",
            "c099b3109d4d031f71b2c18b27300b7a2c1048404057bd03f45eda17e3fb5698",
            "6683773a1b710daf17316668d9ded46c0c98e42e7e9c9e9c52e282b50e70c483",
            "aaed3cb034db491a90cbfeab5ac93f4e084684b2bb5350766e926ab658084868",
            "2890b1ab78cffa1e9d0f275bba12d9478125758ab257042431190695c4c88958",
            "11b8ebe11410ae3e7d739df830eef65b8af09ca2427f101934809feb47ca6d9c",
            "a3be5539c3a9ce32dc47f33794a6c0f0441b3cce341af62356f2fdfaeb2fdf59",
            "91c45fc8fb36e38790aab3734deccacebbb00517422ca3eeac9c022caedd70a1",
            "f209b6de3d5672cd9ead39243680435d57e58f24117865097198a5e1c2e9af4c",
            "e4d974e1014851b29ef9bc3d50980c4e4f0bbe1177c4cde862c2ecc4e580733d",
            "50ea60e30540f6fc7ecaac8a9d6941f66e83f67a7f839d3462ce968537674692",
            "8e4f05d2d112aa010c699fd749add25d8c6ef8201a0f3be16768f51740809cec",
            "3ad431f39e87c0c220a59712668735d6f2aca194f2d763227394a9b81a3bf087",
            "3c598be89358ed2c0baa35aa66508e310992dd8c8da346d8dc26651aad7366b2",
            "4fe94fd6e14e4f66ff0f4fa0aba432a39bd8387c861504b66e5e1774f0781316",
            "eb21672aacfae1ea7dd215af6d2d7acd91baf5817767067f2bfeb8c54d8922aa",
            "4bd68316adffc7ac26cfb317021ac1c75a208441558b46aaa8a00e8cfbc88d91",
        ],
        hash="511c8de798f61c88b61ed6adebd0d80856ae247877d63ae9993a2df1099634f5",
    ),
]


def test_hash_tree() -> None:
    for txs, txhash in BLOCKS:
        txs_bin = map(bytes.fromhex, txs)
        assert hash_tree(txs_bin).hex() == txhash


def test_hash_pair() -> None:
    pair = map(
        bytes.fromhex,
        (
            "138cd20eaf96be8ccc4db19da65aaa2c9f918ed2bba76bd2476c430371e7a196",
            "0dbaa5777b962e87ddcf55dbcec76d72515ed22756e90ae3d221c713afd67074",
        ),
    )
    assert (
        hash_pair(*pair).hex()
        == "429421358ae0ca8aa84fd8451763befc4a21e6c28fed6e4e54cc39503a26ccc8"
    )
