"""Command-line interface for validating and freezing research contracts."""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import sys
from typing import Sequence

from .core import _load_contract_mapping, freeze_contract, load_contract
from .errors import ContractError


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="q-arbor-contract")
    commands = parser.add_subparsers(dest="command", required=True)

    validate = commands.add_parser("validate", help="validate a frozen contract")
    validate.add_argument("input", type=Path)

    freeze = commands.add_parser("freeze", help="freeze a draft contract")
    freeze.add_argument("input", type=Path)
    freeze.add_argument("--output", "-o", type=Path, required=True)

    show_hash = commands.add_parser("show-hash", help="show a verified contract hash")
    show_hash.add_argument("input", type=Path)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        if args.command == "freeze":
            contract = freeze_contract(_load_contract_mapping(args.input))
            contract.write(args.output)
            print(contract.sha256)
            return 0
        contract = load_contract(args.input)
        if args.command == "show-hash":
            print(contract.sha256)
        else:
            print("valid")
        return 0
    except ContractError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except OSError:
        print("error: unable to write contract", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
