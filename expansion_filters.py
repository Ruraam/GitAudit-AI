"""Lightweight lexical masking for Lua, SQL, HCL, Compose and Docker.

For each line return (comments_removed, comments_and_strings_removed).
Only common syntax is covered; this is NOT a language parser.
"""
from __future__ import annotations


def expansion_views(lines: list[str], dialect: str) -> list[tuple[str, str]]:
    if dialect not in {"lua", "sql", "hcl", "compose", "docker"}:
        raise ValueError("Unsupported lexical dialect")

    result: list[tuple[str, str]] = []
    block_end: str | None = None

    for line in lines:
        if dialect == "docker":
            # Dockerfile: only an instruction beginning with # is a comment.
            view = (" " * len(line)) if line.lstrip().startswith("#") else line
            result.append((view, view))
            continue

        no_comments = list(line)
        code_only = list(line)
        quote: str | None = None
        index = 0

        while index < len(line):
            if block_end is not None:
                end = line.find(block_end, index)
                finish = len(line) if end == -1 else end + len(block_end)
                for n in range(index, finish):
                    no_comments[n] = code_only[n] = " "
                index = finish
                if end != -1:
                    block_end = None
                continue

            char = line[index]
            if quote is not None:
                code_only[index] = " "
                if dialect == "sql" and char == quote and line[index:index + 2] == quote * 2:
                    code_only[index + 1] = " "
                    index += 2
                    continue
                if char == "\\" and dialect in {"lua", "hcl", "compose"} and index + 1 < len(line):
                    code_only[index + 1] = " "
                    index += 2
                    continue
                if char == quote:
                    quote = None
                index += 1
                continue

            if dialect == "lua" and line.startswith("--[[", index):
                block_end = "]]"
                finish = index + 4
            elif dialect in {"sql", "hcl"} and line.startswith("/*", index):
                block_end = "*/"
                finish = index + 2
            else:
                finish = -1

            if finish != -1:
                for n in range(index, finish):
                    no_comments[n] = code_only[n] = " "
                index = finish
                continue

            line_comment = (
                (dialect == "lua" and line.startswith("--", index))
                or (dialect == "sql" and line.startswith("--", index))
                or (dialect == "hcl" and (line.startswith("//", index) or char == "#"))
                or (dialect == "compose" and char == "#")
            )
            if line_comment:
                for n in range(index, len(line)):
                    no_comments[n] = code_only[n] = " "
                break

            if char in "'\"":
                quote = char
                code_only[index] = " "
            index += 1

        result.append(("".join(no_comments), "".join(code_only)))

    return result
