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
IDA side of the capa auto-renamer. works in the IDA GUI, idat and idalib (no Qt).

capa results are taken from the database cache written by capa explorer (same netnode),
otherwise capa runs here and writes that cache, so both plugins share one analysis.

every rename is recorded in a netnode with the name it replaced, so it can be undone across sessions.
undo only restores a function whose name is still the one we set; later user edits are kept.

usage from the IDAPython console or a script:

    import capa_rename.ida_backend as rb
    proposals = rb.auto_rename(min_confidence="HIGH", dry_run=True)
    print(rb.format_report(proposals))
    rb.auto_rename(min_confidence="HIGH")
    rb.undo()
"""

import os
import json
import logging
from pathlib import Path
from dataclasses import fields, dataclass

import idc
import ida_ua
import idaapi
import ida_gdl
import ida_idp
import ida_name
import idautils
import ida_bytes
import ida_funcs
import capa.rules
import capa.loader
import ida_kernwin
import capa.ida.helpers
import capa.capabilities.common
import capa.render.result_document as rdoc
from netnode import netnode
from capa.rules.cache import compute_ruleset_cache_identifier
from capa.features.extractors.ida.extractor import IdaFeatureExtractor
from capa.features.extractors.base_extractor import FunctionHandle

from .naming import NameStyle, NamingOptions
from .proposals import (
    Proposal,
    Confidence,
    FunctionSize,
    ScoringOptions,
    assign_names,
    load_overrides,
    build_proposals,
    split_overrides,
)

logger = logging.getLogger(__name__)

RENAMER_NETNODE = "$ com.mandiant.capa.renamer"
NETNODE_HISTORY = "history"

# shared with capa explorer, see capa.ida.plugin.form
CAPA_SETTINGS_NAMESPACE = "capa"
CAPA_SETTINGS_RULE_PATH = "rule_path"
RENAMER_SETTINGS_PREFIX = "renamer_"

COMMENT_HEADER = "capa auto-rename"
COMMENT_MAX_OTHER_RULES = 8

STATUS_AUTO_NAME = "auto-generated name"
STATUS_OURS = "renamed by capa earlier"
STATUS_OVERWRITE = "has a name (overwrite enabled)"
STATUS_NAMED = "already named"
STATUS_LIBRARY = "library function"
STATUS_THUNK = "thunk"
STATUS_NOT_FUNCTION = "not a function start"
STATUS_UP_TO_DATE = "up to date"
STATUS_NO_NAME = "no valid name"
STATUS_RENAMED = "renamed"


class RenamerError(Exception):
    pass


class UserCancelledError(RenamerError):
    pass


class RulesNotConfiguredError(RenamerError):
    pass


@dataclass
class RenamerSettings:
    prefix: str = "capa_"
    style: str = NameStyle.SNAKE.value
    max_length: int = 64
    min_confidence: str = Confidence.HIGH.name
    add_comment: bool = True
    overwrite_named: bool = False
    big_function_bbs: int = 40
    big_function_calls: int = 20
    overrides_path: str = ""

    def naming(self) -> NamingOptions:
        return NamingOptions(prefix=self.prefix, style=NameStyle(self.style), max_length=max(16, self.max_length))

    def overrides(self) -> tuple[dict[str, str], frozenset[str]]:
        """(rule name -> function name, ignored rule names) from the override file"""
        if not self.overrides_path:
            return {}, frozenset()
        return split_overrides(load_overrides(Path(self.overrides_path)))

    def scoring(self, ignored: frozenset[str] = frozenset()) -> ScoringOptions:
        return ScoringOptions(
            ignored_rules=ignored,
            big_function_bbs=max(0, self.big_function_bbs),
            big_function_calls=max(0, self.big_function_calls),
        )


def _ida_settings():
    try:
        import ida_settings

        return ida_settings.IDASettings(CAPA_SETTINGS_NAMESPACE)
    except Exception as e:
        logger.debug("ida-settings unavailable (error: %s)", e)
        return None


def load_settings() -> RenamerSettings:
    settings = RenamerSettings()
    store = _ida_settings()
    if store is None:
        return settings

    for f in fields(RenamerSettings):
        value = store.user.get(RENAMER_SETTINGS_PREFIX + f.name, None)
        if value is not None:
            setattr(settings, f.name, type(getattr(settings, f.name))(value))
    return settings


def save_settings(settings: RenamerSettings):
    store = _ida_settings()
    if store is None:
        raise RenamerError("ida-settings is not available, cannot save settings")

    for f in fields(RenamerSettings):
        store.user[RENAMER_SETTINGS_PREFIX + f.name] = getattr(settings, f.name)


def get_rule_path() -> str:
    """the capa rules directory configured in capa explorer, or $CAPA_RULES"""
    store = _ida_settings()
    path = store.user.get(CAPA_SETTINGS_RULE_PATH, "") if store is not None else ""
    return path or os.environ.get("CAPA_RULES", "")


def set_rule_path(path: str):
    store = _ida_settings()
    if store is not None:
        store.user[CAPA_SETTINGS_RULE_PATH] = path


def _update_wait_box(text: str):
    if idaapi.is_idaq():
        ida_kernwin.replace_wait_box(f"capa auto-rename...{text}")


def _check_cancelled():
    if idaapi.is_idaq() and ida_kernwin.user_cancelled():
        raise UserCancelledError("user cancelled")


class _CancellableFeatureExtractor(IdaFeatureExtractor):
    """report progress and allow the user to cancel, like capa explorer does"""

    def extract_function_features(self, fh: FunctionHandle):
        _check_cancelled()
        _update_wait_box(f"extracting features from function at {fh.inner.start_ea:#x}")
        return super().extract_function_features(fh)


def analyze(rule_path: str | None = None) -> rdoc.ResultDocument:
    """run capa on the database and cache the results where capa explorer finds them"""
    rule_path = rule_path or get_rule_path()
    # note: Path("") is the current directory, so check the string first
    if not rule_path or not Path(rule_path).is_dir():
        raise RulesNotConfiguredError(
            "capa rules directory is not configured: set it in the capa auto-rename settings, "
            "in capa explorer, or via the CAPA_RULES environment variable"
        )
    path = Path(rule_path)

    def on_load_rule(_, i, total):
        _update_wait_box(f"loading capa rules from {path} ({i + 1} of {total})")
        _check_cancelled()

    _update_wait_box("loading rules")
    ruleset = capa.rules.get_rules([path], on_load_rule=on_load_rule)

    _update_wait_box("extracting features")
    extractor = _CancellableFeatureExtractor()
    capabilities = capa.capabilities.common.find_capabilities(ruleset, extractor, disable_progress=True)

    _update_wait_box("collecting results")
    meta = capa.ida.helpers.collect_metadata([path])
    meta.analysis.feature_counts = capabilities.feature_counts
    meta.analysis.library_functions = capabilities.library_functions
    meta.analysis.layout = capa.loader.compute_layout(ruleset, extractor, capabilities.matches)
    doc = rdoc.ResultDocument.from_capa(meta, ruleset, capabilities.matches)

    try:
        capa.ida.helpers.save_cached_results(doc)
        capa.ida.helpers.save_rules_cache_id(compute_ruleset_cache_identifier(ruleset))
    except Exception as e:
        logger.warning("failed to cache capa results in the database (error: %s)", e)

    return doc


def _same_rules(doc: rdoc.ResultDocument, rule_path: str) -> bool:
    """were the cached results produced with the rules directory configured now? see collect_metadata"""
    if not rule_path:
        # nothing to compare with, and nothing to reanalyze with either
        return True
    return Path(rule_path).resolve().absolute().as_posix() in doc.meta.analysis.rules


def get_result_document(reanalyze: bool = False, rule_path: str | None = None) -> rdoc.ResultDocument:
    """
    use the capa results cached in the database when they are valid and were produced with
    the configured rules directory, otherwise analyze.
    """
    rule_path = rule_path or get_rule_path()
    if not reanalyze:
        try:
            if capa.ida.helpers.idb_contains_cached_results():
                doc = capa.ida.helpers.load_and_verify_cached_results()
                if doc is None:
                    logger.warning("cached capa results are not valid for this database, reanalyzing")
                elif not _same_rules(doc, rule_path):
                    logger.warning(
                        "cached capa results were produced with other rules (%s), reanalyzing with %s",
                        ", ".join(doc.meta.analysis.rules),
                        rule_path,
                    )
                else:
                    logger.info("using capa results cached in the database (created %s)", doc.meta.timestamp)
                    return doc
        except Exception as e:
            logger.warning("failed to load cached capa results, reanalyzing (error: %s)", e)

    return analyze(rule_path)


def func_start(ea: int) -> int | None:
    f = ida_funcs.get_func(ea)
    return f.start_ea if f else None


def function_size(ea: int) -> FunctionSize | None:
    f = ida_funcs.get_func(ea)
    if f is None:
        return None

    calls = 0
    insn = ida_ua.insn_t()
    for item in idautils.FuncItems(f.start_ea):
        if ida_ua.decode_insn(insn, item) and ida_idp.is_call_insn(insn):
            calls += 1

    return FunctionSize(basic_blocks=ida_gdl.FlowChart(f, flags=ida_gdl.FC_NOEXT).size, calls=calls)


def is_name_taken(name: str, ea: int) -> bool:
    other = ida_name.get_name_ea(idaapi.BADADDR, name)
    return other != idaapi.BADADDR and other != ea


def has_dummy_name(ea: int) -> bool:
    return ida_bytes.has_dummy_name(ida_bytes.get_full_flags(ea))


def load_history() -> dict[int, dict]:
    """function start -> {"orig": name before the first capa rename ("" for a dummy name), "new": ..., "comment": ...}"""
    raw = netnode.Netnode(RENAMER_NETNODE).get(NETNODE_HISTORY)
    if not raw:
        return {}
    return {int(ea, 16): entry for ea, entry in json.loads(raw).items()}


def save_history(history: dict[int, dict]):
    n = netnode.Netnode(RENAMER_NETNODE)
    if history:
        n[NETNODE_HISTORY] = json.dumps({hex(ea): entry for ea, entry in sorted(history.items())})
    elif n.get(NETNODE_HISTORY):
        del n[NETNODE_HISTORY]


def classify(proposal: Proposal, history: dict[int, dict], overwrite_named: bool):
    """decide whether the function may be renamed, and why (or why not)"""
    ea = proposal.ea
    f = ida_funcs.get_func(ea)
    proposal.current_name = ida_funcs.get_func_name(ea) or ""
    entry = history.get(ea)

    if f is None or f.start_ea != ea:
        proposal.eligible, proposal.status = False, STATUS_NOT_FUNCTION
    elif f.flags & ida_funcs.FUNC_LIB:
        proposal.eligible, proposal.status = False, STATUS_LIBRARY
    elif f.flags & ida_funcs.FUNC_THUNK:
        proposal.eligible, proposal.status = False, STATUS_THUNK
    elif entry is not None and entry.get("new") == proposal.current_name:
        proposal.eligible, proposal.status = True, STATUS_OURS
    elif has_dummy_name(ea):
        proposal.eligible, proposal.status = True, STATUS_AUTO_NAME
    elif overwrite_named:
        proposal.eligible, proposal.status = True, STATUS_OVERWRITE
    else:
        # user names, FLIRT/Lumina/PDB names: they are usually better than anything derived from capa
        proposal.eligible, proposal.status = False, STATUS_NAMED


def compute_proposals(doc: rdoc.ResultDocument, settings: RenamerSettings | None = None) -> list[Proposal]:
    settings = settings or load_settings()

    overrides, ignored = settings.overrides()
    proposals = build_proposals(doc, func_start, function_size, settings.scoring(ignored))

    history = load_history()
    for proposal in proposals:
        classify(proposal, history, settings.overwrite_named)

    assign_names(proposals, settings.naming(), overrides, is_name_taken)

    for proposal in proposals:
        if not proposal.eligible:
            continue
        if proposal.name is None:
            proposal.eligible, proposal.status = False, STATUS_NO_NAME
        elif proposal.name == proposal.current_name:
            proposal.eligible, proposal.status = False, STATUS_UP_TO_DATE

    return proposals


def comment_for(proposal: Proposal) -> str:
    primary = proposal.primary
    lines = [f"{COMMENT_HEADER} [{proposal.confidence.name}]: {primary.rule}"]
    if primary.namespace:
        lines[0] += f" ({primary.namespace})"

    others = proposal.other_rules
    if others:
        shown = ", ".join(others[:COMMENT_MAX_OTHER_RULES])
        lines.append("also: " + shown + (", ..." if len(others) > COMMENT_MAX_OTHER_RULES else ""))
    return "\n".join(lines)


def _replace_comment_block(ea: int, old_block: str, new_block: str):
    """replace our block in the function comment, keeping whatever else the user wrote"""
    comment = idc.get_func_cmt(ea, 0) or ""
    if old_block and old_block in comment:
        comment = comment.replace(old_block, "").strip("\n")
    if new_block:
        comment = f"{comment}\n{new_block}" if comment else new_block
    idc.set_func_cmt(ea, comment, 0)


def _refresh_ui():
    if idaapi.is_idaq():
        ida_kernwin.request_refresh(ida_kernwin.IWID_DISASMS | ida_kernwin.IWID_FUNCS)


def apply(proposals: list[Proposal], add_comment: bool = True, force_named: bool = False) -> tuple[int, int]:
    """
    rename the eligible proposals.

    args:
      force_named: also rename proposals that are only skipped because the function already has a name;
        used when the user explicitly selected them.

    returns:
      (renamed, failed)
    """
    history = load_history()
    renamed = failed = 0

    for proposal in proposals:
        if not proposal.name:
            continue
        if not (proposal.eligible or (force_named and proposal.status == STATUS_NAMED)):
            continue

        ea = proposal.ea
        current = ida_funcs.get_func_name(ea) or ""
        entry = history.get(ea)
        if entry is None or entry.get("new") != current:
            # first rename, or the user renamed the function after our previous rename:
            # what is there now is what undo should bring back.
            entry = {"orig": "" if has_dummy_name(ea) else current, "comment": ""}

        # SN_FORCE: if the name got taken in the meantime, IDA appends a numeric suffix instead of failing
        if not ida_name.set_name(ea, proposal.name, ida_name.SN_NOWARN | ida_name.SN_FORCE):
            logger.warning("failed to rename function at %#x to %s", ea, proposal.name)
            failed += 1
            continue

        entry["new"] = ida_funcs.get_func_name(ea)
        if add_comment:
            block = comment_for(proposal)
            _replace_comment_block(ea, entry.get("comment", ""), block)
            entry["comment"] = block

        history[ea] = entry
        proposal.current_name = entry["new"]
        proposal.eligible, proposal.status = False, STATUS_RENAMED
        renamed += 1

    save_history(history)
    _refresh_ui()
    logger.info("capa auto-rename: renamed %d functions, %d failed", renamed, failed)
    return renamed, failed


def undo(eas: list[int] | None = None) -> tuple[int, int]:
    """
    restore the names (and comments) from before the capa renames.

    args:
      eas: function starts to restore; all recorded functions when None.

    returns:
      (restored, kept): kept counts functions the user renamed since, which are left alone.
    """
    history = load_history()
    targets = sorted(history) if eas is None else [ea for ea in eas if ea in history]
    restored = kept = 0

    for ea in targets:
        entry = history.pop(ea)
        current = ida_funcs.get_func_name(ea) or ""

        if current == entry.get("new"):
            orig = entry.get("orig", "")
            # an empty name makes IDA regenerate the dummy name, e.g. sub_401000.
            # note: SN_FORCE must not be combined with an empty name, the rename silently does nothing then.
            flags = ida_name.SN_NOWARN | (ida_name.SN_FORCE if orig else 0)
            if ida_name.set_name(ea, orig, flags):
                restored += 1
            else:
                logger.warning("failed to restore the name of the function at %#x to %s", ea, orig or "<auto>")
                # keep the entry so that undo can be retried
                history[ea] = entry
                continue
        else:
            logger.info("keeping %s at %#x: renamed by the user after capa auto-rename", current, ea)
            kept += 1

        if entry.get("comment"):
            _replace_comment_block(ea, entry["comment"], "")

    save_history(history)
    _refresh_ui()
    logger.info("capa auto-rename: restored %d functions, kept %d renamed by the user", restored, kept)
    return restored, kept


def select_for_auto_rename(proposals: list[Proposal], min_confidence: Confidence) -> list[Proposal]:
    return [p for p in proposals if p.eligible and p.confidence >= min_confidence]


def auto_rename(
    min_confidence: str | None = None,
    dry_run: bool = False,
    reanalyze: bool = False,
    settings: RenamerSettings | None = None,
) -> list[Proposal]:
    """compute proposals and rename every eligible function at or above `min_confidence`"""
    settings = settings or load_settings()
    threshold = Confidence.parse(min_confidence or settings.min_confidence)

    doc = get_result_document(reanalyze)
    proposals = compute_proposals(doc, settings)
    if not dry_run:
        apply(select_for_auto_rename(proposals, threshold), settings.add_comment)
    return proposals


def format_report(proposals: list[Proposal]) -> str:
    lines = []
    for p in proposals:
        others = ", ".join(p.other_rules)
        lines.append(
            f"{p.ea:#x}  {p.confidence.name:<6}  {p.current_name:<28} -> {p.name or '-':<44}  "
            f"[{p.status}]  {p.primary.rule}" + (f"  (also: {others})" if others else "")
        )
    return "\n".join(lines)
