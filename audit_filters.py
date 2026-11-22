"""Lightweight source-aware filtering used only to reduce heuristic false positives.

The scanners are intentionally limited. They do not replace a complete language
parser, and findings must never be treated as confirmed vulnerabilities.
"""

from __future__ import annotations

import io
import re
import tokenize


def _blank(characters: list[str], start: int, end: int) -> None:
    """Mask text without changing its positions or line lengths."""
    for index in range(start, end):
        if characters[index] not in "\r\n":
            characters[index] = " "


def python_code_lines(lines: list[str]) -> list[str]:
    """Suppress Python comments and string tokens for code-only rules.

    Syntax errors fall back to the previous conservative comment-only filter.
    Real expressions inside complex f-strings may require a dedicated AST parser.
    """
    source = "\n".join(lines) + "\n"
    masked = [list(line) for line in lines]
    try:
        tokens = list(tokenize.generate_tokens(io.StringIO(source).readline))
    except (tokenize.TokenError, IndentationError, SyntaxError):
        return [
            " " * len(line) if line.lstrip().startswith("#") else line
            for line in lines
        ]
    for token in tokens:
        if token.type not in (tokenize.STRING, tokenize.COMMENT):
            continue
        (first_line, first_col) = token.start
        (last_line, last_col) = token.end
        for row in range(first_line - 1, min(last_line, len(masked))):
            left = first_col if row == first_line - 1 else 0
            right = last_col if row == last_line - 1 else len(masked[row])
            _blank(masked[row], left, min(right, len(masked[row])))
    return ["".join(line) for line in masked]


_RUST_RAW_START = re.compile(r'(?:br|r)(#{0,8})"')
_RUST_CHAR = re.compile(r"'(?:\\.|[^'\\])'")


def rust_scan_views(lines: list[str]) -> list[tuple[str, str]]:
    """Return (comment-free source, comment-and-string-free source) per line.

    Handles common Rust string forms, including raw strings, and multiline block
    comments. Not a Rust lexer: macros and unusual token sequences can still fool
    the heuristic.
    """
    output: list[tuple[str, str]] = []
    block_depth = 0
    string_open = False
    string_escape = False
    raw_closer: str | None = None

    for line in lines:
        code = list(line)
        comments_removed = list(line)
        index = 0

        while index < len(line):
            if block_depth:
                # Rust block comments can nest, unlike C-style comments.
                if line.startswith("/*", index):
                    block_depth += 1
                    finish = index + 2
                elif line.startswith("*/", index):
                    block_depth -= 1
                    finish = index + 2
                else:
                    finish = index + 1
                _blank(code, index, finish)
                _blank(comments_removed, index, finish)
                index = finish
                continue

            if raw_closer is not None:
                end = line.find(raw_closer, index)
                finish = len(line) if end == -1 else end + len(raw_closer)
                _blank(code, index, finish)
                if end != -1:
                    raw_closer = None
                index = finish
                continue

            if string_open:
                start = index
                while index < len(line):
                    char = line[index]
                    index += 1
                    if string_escape:
                        string_escape = False
                    elif char == "\\":
                        string_escape = True
                    elif char == '"':
                        string_open = False
                        break
                _blank(code, start, index)
                continue

            if line.startswith("//", index):
                _blank(code, index, len(line))
                _blank(comments_removed, index, len(line))
                break

            if line.startswith("/*", index):
                _blank(code, index, index + 2)
                _blank(comments_removed, index, index + 2)
                block_depth = 1
                index += 2
                continue

            previous = line[index - 1] if index > 0 else ""
            if not (previous.isalnum() or previous == "_"):
                match = _RUST_RAW_START.match(line, index)
                if match:
                    raw_closer = '"' + match.group(1)
                    end = match.end()
                    _blank(code, index, end)
                    index = end
                    continue

            if line[index] == '"':
                _blank(code, index, index + 1)
                string_open = True
                string_escape = False
                index += 1
                continue

            if line[index] == "'":
                match = _RUST_CHAR.match(line, index)
                if match:
                    _blank(code, index, match.end())
                    index = match.end()
                    continue

            index += 1

        output.append(("".join(comments_removed), "".join(code)))
    return output


def shell_without_comments(line: str) -> str:
    """Strip Bash trailing comments, keeping # inside simple quoted arguments."""
    quote: str | None = None
    escape = False

    for index, char in enumerate(line):
        if escape:
            escape = False
            continue
        if char == "\\" and quote != "'":
            escape = True
            continue
        if quote:
            if char == quote:
                quote = None
            continue
        if char in "'\"":
            quote = char
        elif char == "#" and (
            index == 0 or line[index - 1].isspace() or line[index - 1] in ";|&()"
        ):
            return line[:index]
    return line


def hash_language_code(line: str, *, powershell: bool = False) -> str:
    """Mask simple Ruby/PowerShell strings and hash comments, preserving offsets.

    This is intentionally line-oriented: it does not recognize heredocs or
    PowerShell here-strings, and cannot replace a real language parser.
    """
    result = list(line)
    quote: str | None = None
    escape = False
    escape_character = "\`" if powershell else "\\"

    for index, char in enumerate(line):
        if quote is not None:
            result[index] = " "
            if escape:
                escape = False
            elif char == escape_character:
                escape = True
            elif char == quote:
                quote = None
            continue
        if char in "'\"":
            quote = char
            result[index] = " "
        elif char == "#":
            for remainder in range(index, len(result)):
                result[remainder] = " "
            break
    return "".join(result)


def js_scan_views(lines: list[str]) -> list[tuple[str, str]]:
    """Mask JS/TS single/double/template strings and both comment forms.

    Returns (comment-free, comments-and-literals-free) lines with intact
    offsets. Template interpolations and regex literals are not parsed,
    so this is a lightweight heuristic filter, not a JavaScript parser.
    """
    output: list[tuple[str, str]] = []
    block_comment = False
    quote: str | None = None
    escaped = False

    for line in lines:
        no_comments = list(line)
        only_code = list(line)
        index = 0

        while index < len(line):
            if block_comment:
                end = line.find("*/", index)
                finish = len(line) if end < 0 else end + 2
                _blank(no_comments, index, finish)
                _blank(only_code, index, finish)
                index = finish
                if end >= 0:
                    block_comment = False
                continue

            if quote is not None:
                char = line[index]
                _blank(only_code, index, index + 1)
                if escaped:
                    escaped = False
                elif char == "\\":
                    escaped = True
                elif char == quote:
                    quote = None
                index += 1
                continue

            if line.startswith("//", index):
                _blank(no_comments, index, len(line))
                _blank(only_code, index, len(line))
                break
            if line.startswith("/*", index):
                block_comment = True
                _blank(no_comments, index, index + 2)
                _blank(only_code, index, index + 2)
                index += 2
                continue
            if line[index] in ("'", '"', chr(96)):
                quote = line[index]
                escaped = False
                _blank(only_code, index, index + 1)
            index += 1

        output.append(("".join(no_comments), "".join(only_code)))

    return output
