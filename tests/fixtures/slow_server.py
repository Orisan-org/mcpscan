from __future__ import annotations

import argparse
import time

from mcp.server.fastmcp import FastMCP


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--delay", type=float, default=5.0)
    return parser.parse_args()


args = parse_args()
time.sleep(args.delay)

mcp = FastMCP("slow-benign-server")


@mcp.tool()
def search_docs(query: str) -> str:
    """Search public documentation."""
    return f"Results for {query}"


@mcp.resource("docs://readme")
def readme() -> str:
    return "Public README"


@mcp.prompt()
def summarize_ticket(ticket: str) -> str:
    return f"Summarize this ticket: {ticket}"


if __name__ == "__main__":
    mcp.run()
