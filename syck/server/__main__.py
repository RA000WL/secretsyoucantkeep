import argparse
import sys

from syck.server import HOST, PORT, serve


def main() -> int:
    ap = argparse.ArgumentParser(prog="syck-server")
    ap.add_argument("--host", default=HOST, help=f"Bind address (default: {HOST})")
    ap.add_argument("--port", type=int, default=PORT, help=f"Port (default: {PORT})")
    ap.add_argument("--api-key", help="Require Bearer token via Authorization header")
    args = ap.parse_args()
    serve(args.host, args.port, args.api_key)
    return 0


if __name__ == "__main__":
    sys.exit(main())
