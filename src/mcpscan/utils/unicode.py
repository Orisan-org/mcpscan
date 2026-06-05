ZERO_WIDTH_CHARS = ("\u200b", "\u200c", "\u200d", "\ufeff")


def contains_zero_width(value: str) -> bool:
    return any(char in value for char in ZERO_WIDTH_CHARS)
