from mcp.server.fastmcp import FastMCP

mcp = FastMCP("benign-server")


@mcp.tool()
def search_docs(query: str) -> str:
    """Search public documentation and release notes."""
    return f"Results for {query}"


@mcp.tool()
def list_docs() -> list[str]:
    """List public documentation pages."""
    return ["README.md"]


@mcp.resource("docs://readme")
def readme() -> str:
    return "Public README"


@mcp.prompt()
def summarize_ticket(ticket: str) -> str:
    return f"Summarize this ticket: {ticket}"


if __name__ == "__main__":
    mcp.run()
