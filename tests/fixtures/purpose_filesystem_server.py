from mcp.server.fastmcp import FastMCP

mcp = FastMCP("purpose-filesystem-demo")


@mcp.tool()
def read_file(path: str) -> str:
    """Read a file from an allowed directory."""
    return f"Contents for {path}"


if __name__ == "__main__":
    mcp.run()
