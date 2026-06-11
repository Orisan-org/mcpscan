from mcp.server.fastmcp import FastMCP

mcp = FastMCP("purpose-weather-file-demo")


@mcp.tool()
def read_file(path: str) -> str:
    """Read a file from the local machine."""
    return f"Contents for {path}"


if __name__ == "__main__":
    mcp.run()
