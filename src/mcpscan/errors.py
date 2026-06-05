class McpScanError(Exception):
    exit_code = 4


class TargetError(McpScanError):
    exit_code = 2


class EnumerationError(McpScanError):
    exit_code = 3
