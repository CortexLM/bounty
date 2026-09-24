"""``bounty-challenge serve``: the container entry point."""

import argparse

import uvicorn

from .app import create_app
from .settings import Settings


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(prog="bounty-challenge")
    commands = parser.add_subparsers(dest="command", required=True)
    serve = commands.add_parser("serve", help="serve the challenge HTTP API")
    serve.add_argument("--host", default="0.0.0.0")
    serve.add_argument("--port", type=int, default=8000)
    args = parser.parse_args(argv)
    uvicorn.run(
        create_app(Settings.from_env()),
        host=args.host,
        port=args.port,
        proxy_headers=False,
        server_header=False,
        log_level="info",
    )


if __name__ == "__main__":
    main()
