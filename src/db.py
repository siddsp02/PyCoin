"""Bitcoin uses Berkeley DB for its search engine.
In this case, the Python standard library's SQLite
will be used.
"""

import sqlite3

con = sqlite3.connect("blockchain.db")
cur = con.cursor()


def main() -> None:
    ...


if __name__ == "__main__":
    main()
