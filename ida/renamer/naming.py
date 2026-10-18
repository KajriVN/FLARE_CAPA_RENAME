# Copyright 2026 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""
derive function names from capa rule names.

this module must not import IDA so that it can be tested outside of IDA.

the produced names always match `^[A-Za-z_][A-Za-z0-9_]*$`, which IDA accepts as an identifier
regardless of the NameChars configuration, and which the decompiler can print as-is.

example:

    "check for time delay via QueryPerformanceCounter" -> "capa_check_time_delay_QueryPerformanceCounter"
    "encrypt data using HC-128 via WolfSSL"            -> "capa_encrypt_data_HC_128_WolfSSL"
    "use process Doppelgänging"                        -> "capa_use_process_Doppelganging"
"""

import re
import unicodedata
from enum import Enum
from dataclasses import dataclass
from collections.abc import Callable

IDENT_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")

# articles and most prepositions carry little information in an identifier.
# conjunctions ("or", "and") and directions ("to", "from") are kept because dropping them changes the meaning,
# e.g. "add user account group" vs "add user account to group".
STOPWORDS = frozenset(("a", "an", "the", "for", "of", "with", "via", "using", "by", "as", "at", "into", "on", "in"))

# the platform/runtime is a property of the whole binary, so it adds nothing to a function name.
# e.g. "access camera in .NET on Android" -> "access camera"
PLATFORM_QUALIFIER_RE = re.compile(
    r"\s+(?:on|in|for)\s+(?:windows|linux|android|macos|mac os|os x|ios|freebsd|esxi|\.net)(?=\s|$)",
    re.IGNORECASE,
)

# names that IDA regenerates on its own: a dummy prefix followed by only hex digits, e.g. `sub_401000`.
# a user name with this shape is treated as an auto-generated one and may be replaced by IDA later.
IDA_DUMMY_NAME_RE = re.compile(
    r"^(?:sub|loc|locret|off|seg|asc|byte|word|dword|qword|oword|xmmword|ymmword|zmmword|tbyte|flt|dbl|"
    r"packreal|stru|unk|algn|nullsub|j|def|jpt|funcs|custdata|bytes)_[0-9A-Fa-f]+$",
    re.IGNORECASE,
)

# C/C++ keywords: the decompiler would print such a function name confusingly.
RESERVED_WORDS = frozenset(
    (
        "asm",
        "auto",
        "bool",
        "break",
        "case",
        "catch",
        "char",
        "class",
        "const",
        "constexpr",
        "continue",
        "default",
        "delete",
        "do",
        "double",
        "else",
        "enum",
        "explicit",
        "extern",
        "false",
        "float",
        "for",
        "friend",
        "goto",
        "if",
        "inline",
        "int",
        "long",
        "mutable",
        "namespace",
        "new",
        "noexcept",
        "nullptr",
        "operator",
        "private",
        "protected",
        "public",
        "register",
        "restrict",
        "return",
        "short",
        "signed",
        "sizeof",
        "static",
        "struct",
        "switch",
        "template",
        "this",
        "throw",
        "true",
        "try",
        "typedef",
        "typename",
        "union",
        "unsigned",
        "using",
        "virtual",
        "void",
        "volatile",
        "while",
    )
)

# IDA accepts much longer names (MAXNAMELEN), but long names make listings unreadable.
DEFAULT_MAX_LENGTH = 64

# when truncating, keep at least this many tokens so the name still reads as "verb object".
MIN_TOKENS = 2


class NameStyle(str, Enum):
    # snake_case, keep the original case of acronyms and API names: capa_hash_data_SHA256
    SNAKE = "snake"
    # snake_case, all lower case: capa_hash_data_sha256
    LOWER = "lower"
    # PascalCase: capa_HashDataSHA256
    PASCAL = "pascal"


@dataclass(frozen=True)
class NamingOptions:
    prefix: str = "capa_"
    style: NameStyle = NameStyle.SNAKE
    max_length: int = DEFAULT_MAX_LENGTH


DEFAULT_NAMING = NamingOptions()


def _to_ascii(s: str) -> str:
    """transliterate to ASCII, e.g. "Doppelgänging" -> "Doppelganging", drop what cannot be transliterated"""
    return unicodedata.normalize("NFKD", s).encode("ascii", "ignore").decode("ascii")


def tokenize(phrase: str, drop_stopwords: bool = True) -> list[str]:
    """split a rule name (or user supplied name) into identifier-safe tokens"""
    phrase = PLATFORM_QUALIFIER_RE.sub("", phrase)

    tokens: list[str] = []
    for word in re.split(r"[\s/]+", _to_ascii(phrase)):
        if drop_stopwords and word.lower() in STOPWORDS:
            continue

        # "HC-128" -> "HC_128", ".NET" -> "NET", "(MBR)" -> "MBR", "Chromium-based" -> "Chromium_based"
        token = re.sub(r"[^A-Za-z0-9]+", "_", word).strip("_")
        if token:
            tokens.append(token)
    return tokens


def _style_tokens(tokens: list[str], style: NameStyle) -> list[str]:
    if style == NameStyle.LOWER:
        return [t.lower() for t in tokens]
    if style == NameStyle.PASCAL:
        # "ws_ftp" -> "WsFtp", "HC_128" -> "HC128"
        return ["".join(part[0].upper() + part[1:] for part in t.split("_") if part) for t in tokens]
    return tokens


def _join(tokens: list[str], style: NameStyle) -> str:
    return ("" if style == NameStyle.PASCAL else "_").join(tokens)


def _fit(prefix: str, tokens: list[str], style: NameStyle, max_length: int) -> str:
    """join tokens, dropping trailing tokens (then hard-truncating) to respect max_length"""
    max_length = max(max_length, len(prefix) + 8)
    tokens = list(tokens)
    body = _join(tokens, style)
    while len(prefix) + len(body) > max_length and len(tokens) > MIN_TOKENS:
        tokens.pop()
        body = _join(tokens, style)

    name = prefix + body
    if len(name) > max_length:
        name = name[:max_length].rstrip("_")
    return name


def make_safe(name: str) -> str | None:
    """
    final guard applied to every candidate name.

    returns None when no valid identifier can be produced (e.g. empty input).
    """
    if not name:
        return None

    if not (name[0].isalpha() or name[0] == "_"):
        # e.g. "64-bit execution via heavens gate" without a prefix
        name = "_" + name

    if name.lower() in RESERVED_WORDS or IDA_DUMMY_NAME_RE.match(name):
        name = name + "_"

    if not IDENT_RE.match(name):
        return None
    return name


def derive_name(rule_name: str, options: NamingOptions = DEFAULT_NAMING, override: str | None = None) -> str | None:
    """
    derive a function name from a capa rule name.

    args:
      rule_name: the capa rule name, e.g. "hash data using SHA256"
      options: naming options
      override: a name body chosen by the user for this rule; it is sanitized but not restyled,
        and the prefix is still applied so that all generated names are recognizable.

    returns:
      a valid identifier, or None if the rule name contains nothing usable.
    """
    prefix = _sanitize_prefix(options.prefix)

    if override:
        tokens = tokenize(override, drop_stopwords=False)
        style = NameStyle.SNAKE
    else:
        tokens = tokenize(rule_name)
        if not tokens:
            # a rule name made only of stopwords is unlikely, but keep the words rather than produce nothing
            tokens = tokenize(rule_name, drop_stopwords=False)
        style = options.style
        tokens = _style_tokens(tokens, style)

    if not tokens:
        return None

    return make_safe(_fit(prefix, tokens, style, options.max_length))


def _sanitize_prefix(prefix: str) -> str:
    return re.sub(r"[^A-Za-z0-9_]+", "_", _to_ascii(prefix or ""))


def make_unique(name: str, is_taken: Callable[[str], bool], max_length: int = DEFAULT_MAX_LENGTH) -> str:
    """
    return `name`, or `name_2`, `name_3`, ... for the first variant that is not taken.

    the suffix is appended after truncation so that it is never cut off.
    """
    if not is_taken(name):
        return name

    i = 2
    while True:
        suffix = f"_{i}"
        candidate = name[: max(1, max_length - len(suffix))].rstrip("_") + suffix
        if not is_taken(candidate):
            return candidate
        i += 1
