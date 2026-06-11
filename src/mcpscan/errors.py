class McpScanError(Exception):
    exit_code = 4


class TargetError(McpScanError):
    exit_code = 2


class EnumerationError(McpScanError):
    exit_code = 3


def unwrap_exception_group(exc: BaseException) -> BaseException:
    """Return the innermost exception from nested ExceptionGroup wrappers."""
    current = exc
    while isinstance(current, BaseExceptionGroup) and current.exceptions:
        current = current.exceptions[0]
    return current


def exception_summary(exc: BaseException) -> str:
    root = unwrap_exception_group(exc)
    message = str(root).strip()
    if message:
        return f"{root.__class__.__name__}: {message}"
    return root.__class__.__name__
