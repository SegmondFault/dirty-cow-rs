#!/usr/bin/env python3
from pathlib import Path


PASSWD = Path("/etc/passwd")
ROOT_LINE = "root:x:0:0:root:/root:/bin/bash"


def main() -> None:
    lines = PASSWD.read_text().splitlines()
    if not lines:
        raise SystemExit("/etc/passwd is empty; refusing to improvise.")

    lines[0] = ROOT_LINE
    PASSWD.write_text("\n".join(lines) + "\n")


if __name__ == "__main__":
    main()
