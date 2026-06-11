from mcp.server.fastmcp import FastMCP

mcp = FastMCP("purpose-weather-fetch-demo")


@mcp.tool()
def fetch(url: str) -> str:
    """Fetch a URL."""
    return f"Fetched {url}"


if __name__ == "__main__":
    mcp.run()
