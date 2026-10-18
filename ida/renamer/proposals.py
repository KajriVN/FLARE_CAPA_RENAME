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
turn a capa result document into at most one rename proposal per function.

this module must not import IDA. the IDA specific bits (which function contains an address,
how big a function is, which names are taken) are passed in as callables.

how a proposal is built for one function:

  1. collect the capability rules that matched inside the function (function, basic block and
     instruction scope; file scope matches have no function and are ignored).
  2. drop rules that another matched rule depends on via `match:`, e.g. when both
     "inject dll" and "write process memory" match, "inject dll" is the better description.
  3. split the rest into strong and weak evidence. weak evidence says that something is
     present in the function ("reference AES constants") rather than what the function does.
  4. rank by score, pick the best as the primary rule, and derive the name from it.
  5. grade the confidence:
       HIGH:   exactly one strong capability remains
       MEDIUM: up to `max_related` strong capabilities, all in the same namespace family
       LOW:    anything else (dispatcher-like functions, or weak evidence only)
     large functions (many basic blocks or many calls) are downgraded one or two levels,
     since one capability rarely describes all of what they do.
"""

import re
import json
import logging
from enum import IntEnum
from typing import Any
from pathlib import Path
from dataclasses import field, dataclass
from collections.abc import Callable, Iterable

from capa.features.address import AbsoluteVirtualAddress

from .naming import DEFAULT_NAMING, NamingOptions, derive_name, make_unique

logger = logging.getLogger(__name__)


class Confidence(IntEnum):
    LOW = 1
    MEDIUM = 2
    HIGH = 3

    @classmethod
    def parse(cls, s: str) -> "Confidence":
        return cls[s.strip().upper()]


# only these static scopes can be attributed to a single function.
CODE_SCOPES = ("function", "basic block", "instruction")

# basic block and instruction rules describe a tight, local pattern;
# function rules may combine features spread across a large function.
SCOPE_WEIGHT = {"instruction": 1.0, "basic block": 1.0, "function": 0.9}

WEAK_FACTOR = 0.3

# rule names that describe presence of data/artifacts rather than behavior,
# or behavior that is incidental in common runtime code.
DEFAULT_WEAK_RULE_PATTERNS = (
    r"^reference\b",
    r"^contain\b",
    r"^(?:packed|compiled|linked|obfuscated|packaged|protected)\b",
    # the MSVC CRT __security_init_cookie mixes GetTickCount/QueryPerformanceCounter into the cookie
    r"^check for time delay via (?:GetTickCount|QueryPerformanceCounter)\b",
)

# namespaces that describe the build or the file, not what a function does.
DEFAULT_WEAK_NAMESPACE_PREFIXES = (
    "compiler/",
    "linking/",
    "anti-analysis/packer/",
    "malware-family/",
)


@dataclass(frozen=True)
class FunctionSize:
    basic_blocks: int
    # number of call instructions
    calls: int


@dataclass(frozen=True)
class ScoringOptions:
    weak_rule_patterns: tuple[str, ...] = DEFAULT_WEAK_RULE_PATTERNS
    weak_namespace_prefixes: tuple[str, ...] = DEFAULT_WEAK_NAMESPACE_PREFIXES
    # rules never used as evidence, e.g. rules that produce false positives on the analyzed code base
    ignored_rules: frozenset[str] = frozenset()
    # how many related capabilities can still yield MEDIUM confidence
    max_related: int = 3
    # functions bigger than this are downgraded one confidence level, and two levels above twice this.
    # a capability found in a function with many calls rarely describes the whole function.
    # 0 disables the check.
    big_function_bbs: int = 40
    big_function_calls: int = 20

    def size_penalty(self, size: FunctionSize) -> int:
        penalty = 0
        for factor in (1, 2):
            if (self.big_function_bbs and size.basic_blocks > factor * self.big_function_bbs) or (
                self.big_function_calls and size.calls > factor * self.big_function_calls
            ):
                penalty = factor
        return penalty

    def is_weak(self, rule_name: str, namespace: str) -> bool:
        if any(re.search(p, rule_name, re.IGNORECASE) for p in self.weak_rule_patterns):
            return True
        return any((namespace + "/").startswith(p) for p in self.weak_namespace_prefixes)


DEFAULT_SCORING = ScoringOptions()


@dataclass
class Candidate:
    rule: str
    namespace: str
    scope: str
    weak: bool
    # number of match locations within the function
    locations: int = 0
    # rule names and namespaces referenced via `match:` in the successful match trees
    refs: set[str] = field(default_factory=set)

    @property
    def score(self) -> float:
        weight = SCOPE_WEIGHT.get(self.scope, 0.5)
        if self.weak:
            weight *= WEAK_FACTOR
        # prefer the more specific namespace, e.g. data-manipulation/hashing/sha256 over data-manipulation/hashing
        depth = len(self.namespace.split("/")) if self.namespace else 0
        return weight + 0.02 * depth

    def sort_key(self):
        return (-self.score, self.rule)


def namespace_family(namespace: str) -> str:
    """e.g. "host-interaction/process/create" -> "host-interaction/process" """
    return "/".join(namespace.split("/")[:2])


@dataclass
class Proposal:
    ea: int
    primary: Candidate
    # other strong capabilities that remain after removing dependencies, best first
    supporting: list[Candidate]
    weak: list[Candidate]
    subsumed: list[Candidate]
    confidence: Confidence
    reasons: list[str]

    # set by the IDA backend
    current_name: str = ""
    eligible: bool = True
    status: str = ""

    # set by assign_names
    name: str | None = None

    @property
    def other_rules(self) -> list[str]:
        """rules shown next to the primary rule, strongest first"""
        return [c.rule for c in self.supporting + self.weak if c is not self.primary]


def is_capability_rule(meta) -> bool:
    """keep in sync with capa.render.utils.capability_rules"""
    if meta.lib:
        return False
    if (meta.namespace or "").startswith("internal/"):
        return False
    if meta.is_subscope_rule:
        return False
    maec = meta.maec
    return not any(
        (
            maec.analysis_conclusion,
            maec.analysis_conclusion_ov,
            maec.malware_family,
            maec.malware_category,
            maec.malware_category_ov,
        )
    )


def collect_match_refs(match) -> set[str]:
    """collect the targets of `match:` features in the successful parts of a match tree"""
    refs: set[str] = set()
    stack = [match]
    while stack:
        m = stack.pop()
        if not m.success:
            continue

        node = m.node
        if node.type == "feature" and node.feature.type == "match":
            refs.add(node.feature.match)

        stack.extend(m.children)
    return refs


def _scope_name(scope: Any) -> str | None:
    return getattr(scope, "value", scope)


def collect_candidates(
    doc, func_start: Callable[[int], int | None], scoring: ScoringOptions = DEFAULT_SCORING
) -> dict[int, dict[str, Candidate]]:
    """
    args:
      doc: capa.render.result_document.ResultDocument
      func_start: maps an address to the start of its containing function, or None.

    returns:
      function start -> rule name -> Candidate
    """
    by_function: dict[int, dict[str, Candidate]] = {}

    for rule in doc.rules.values():
        meta = rule.meta
        if not is_capability_rule(meta) or meta.name in scoring.ignored_rules:
            continue

        scope = _scope_name(meta.scopes.static)
        if scope not in CODE_SCOPES:
            continue

        namespace = meta.namespace or ""
        weak = scoring.is_weak(meta.name, namespace)

        for addr_, match in rule.matches:
            addr = addr_.to_capa()
            if not isinstance(addr, AbsoluteVirtualAddress):
                continue

            fva = func_start(int(addr))
            if fva is None:
                # rule match address is not located in a defined function
                continue

            candidates = by_function.setdefault(fva, {})
            candidate = candidates.get(meta.name)
            if candidate is None:
                candidate = Candidate(rule=meta.name, namespace=namespace, scope=scope, weak=weak)
                candidates[meta.name] = candidate

            candidate.locations += 1
            candidate.refs |= collect_match_refs(match)

    return by_function


def find_subsumed(candidates: Iterable[Candidate]) -> set[str]:
    """find candidates that are a dependency of another candidate in the same function"""
    candidates = list(candidates)
    subsumed: set[str] = set()
    for outer in candidates:
        for ref in outer.refs:
            for inner in candidates:
                if inner.rule == outer.rule:
                    continue
                if inner.rule == ref or inner.namespace == ref or inner.namespace.startswith(ref + "/"):
                    subsumed.add(inner.rule)
    return subsumed


def build_proposal(
    fva: int,
    candidates: dict[str, Candidate],
    size: FunctionSize | None = None,
    scoring: ScoringOptions = DEFAULT_SCORING,
) -> Proposal | None:
    if not candidates:
        return None

    subsumed_names = find_subsumed(candidates.values())
    remaining = [c for c in candidates.values() if c.rule not in subsumed_names]
    if not remaining:
        # only possible with circular dependencies, which capa does not allow; be defensive anyway
        remaining = list(candidates.values())
        subsumed_names = set()
    remaining.sort(key=Candidate.sort_key)

    subsumed = sorted((c for c in candidates.values() if c.rule in subsumed_names), key=Candidate.sort_key)
    strong = [c for c in remaining if not c.weak]
    weak = [c for c in remaining if c.weak]

    reasons: list[str] = []
    if strong:
        primary = strong[0]
        families = {namespace_family(c.namespace) for c in strong}
        if len(strong) == 1:
            confidence = Confidence.HIGH
            reasons.append("single capability")
        elif len(families) == 1 and len(strong) <= scoring.max_related:
            confidence = Confidence.MEDIUM
            reasons.append(f"{len(strong)} related capabilities in {next(iter(families)) or '<no namespace>'}")
        else:
            confidence = Confidence.LOW
            reasons.append(f"{len(strong)} capabilities across {len(families)} namespace families")
    else:
        primary = weak[0]
        confidence = Confidence.LOW
        reasons.append("only weak evidence (references, artifacts)")

    penalty = scoring.size_penalty(size) if size is not None else 0
    if penalty:
        confidence = Confidence(max(Confidence.LOW, confidence - penalty))
        reasons.append(f"large function ({size.basic_blocks} basic blocks, {size.calls} calls)")

    if subsumed:
        reasons.append("ignored dependencies: " + ", ".join(c.rule for c in subsumed))

    return Proposal(
        ea=fva,
        primary=primary,
        supporting=[c for c in strong if c is not primary],
        weak=[c for c in weak if c is not primary],
        subsumed=subsumed,
        confidence=confidence,
        reasons=reasons,
    )


def build_proposals(
    doc,
    func_start: Callable[[int], int | None],
    function_size: Callable[[int], FunctionSize | None] | None = None,
    scoring: ScoringOptions = DEFAULT_SCORING,
) -> list[Proposal]:
    proposals = []
    for fva, candidates in sorted(collect_candidates(doc, func_start, scoring).items()):
        proposal = build_proposal(fva, candidates, function_size(fva) if function_size else None, scoring)
        if proposal is not None:
            proposals.append(proposal)
    return proposals


def assign_names(
    proposals: list[Proposal],
    options: NamingOptions = DEFAULT_NAMING,
    overrides: dict[str, str] | None = None,
    is_taken: Callable[[str, int], bool] = lambda name, ea: False,
):
    """
    set `Proposal.name` to a valid name that is unique among the proposals and the database.

    eligible proposals are processed first so that they get the plain name rather than a numbered one.
    processing order is otherwise by address, so the result is deterministic.

    args:
      is_taken: (name, ea) -> True if `name` is already used in the database by something other than `ea`
    """
    overrides = overrides or {}
    used: dict[str, int] = {}

    for proposal in sorted(proposals, key=lambda p: (not p.eligible, p.ea)):
        base = derive_name(proposal.primary.rule, options, overrides.get(proposal.primary.rule))
        if base is None:
            proposal.name = None
            continue

        def taken(name: str, ea=proposal.ea) -> bool:
            return (name in used and used[name] != ea) or is_taken(name, ea)

        proposal.name = make_unique(base, taken, options.max_length)
        used[proposal.name] = proposal.ea


def load_overrides(path: Path) -> dict[str, str | None]:
    """
    load a mapping from rule name to the name to use instead of the derived one.
    an empty value (null) means: ignore this rule, e.g. because it produces false positives.

    YAML or JSON, e.g.:

        hash data using SHA256: sha256_transform
        encrypt data using RC4 PRGA: rc4_crypt
        get geographical location: null
    """
    text = path.read_text(encoding="utf-8")
    if path.suffix.lower() == ".json":
        data = json.loads(text)
    else:
        import yaml

        data = yaml.safe_load(text)

    if not data:
        return {}
    if not isinstance(data, dict):
        raise ValueError(f"{path}: expected a mapping of rule name to function name")
    return {str(k): (str(v) if v else None) for k, v in data.items()}


def split_overrides(overrides: dict[str, str | None]) -> tuple[dict[str, str], frozenset[str]]:
    """split loaded overrides into (rule name -> function name, ignored rule names)"""
    names = {k: v for k, v in overrides.items() if v}
    ignored = frozenset(k for k, v in overrides.items() if not v)
    return names, ignored
