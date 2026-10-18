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
IDA plugin: preview and apply function names derived from capa rule matches.

  - Edit > Plugins > FLARE capa auto-rename (Alt-Shift-F5) opens the proposal list.
  - right click in the list:
      Rename selected / Rename all >= min confidence / Undo selected / Undo all / Re-run capa / Settings
  - double click a row to jump to the function.
"""

import logging

import idc
import idaapi
import ida_kernwin
import capa.ida.helpers

from . import ida_backend as backend
from .naming import NameStyle
from .proposals import Proposal, Confidence

logger = logging.getLogger(__name__)

CHOOSER_TITLE = "capa auto-rename"
ACTION_PREFIX = "capa_renamer:"


class RenamerController:
    """holds the capa results and the current proposals, shared by the chooser and the actions"""

    def __init__(self):
        self.doc = None
        self.proposals: list[Proposal] = []
        self.chooser: ProposalChooser | None = None

    def load(self, reanalyze: bool = False, ask_for_rules: bool = True) -> bool:
        needs_rules = False
        ida_kernwin.show_wait_box("capa auto-rename")
        try:
            if reanalyze or self.doc is None:
                self.doc = backend.get_result_document(reanalyze=reanalyze)
            self.recompute()
            return True
        except backend.RulesNotConfiguredError as e:
            logger.warning("%s", e)
            needs_rules = True
        except backend.UserCancelledError:
            logger.info("user cancelled")
            return False
        except backend.RenamerError as e:
            capa.ida.helpers.inform_user_ida_ui(str(e))
            logger.error("%s", e)
            return False
        except Exception as e:
            capa.ida.helpers.inform_user_ida_ui("capa auto-rename failed")
            logger.exception("capa auto-rename failed (error: %s)", e)
            return False
        finally:
            ida_kernwin.hide_wait_box()

        # first run without a rules directory: ask for it here, after the wait box is gone, then retry once
        if needs_rules and ask_for_rules and edit_settings() and backend.get_rule_path():
            return self.load(reanalyze, ask_for_rules=False)
        return False

    def recompute(self):
        """refresh proposals from the cached capa results, e.g. after renames or settings changes"""
        if self.doc is None:
            return
        self.proposals = backend.compute_proposals(self.doc, backend.load_settings())
        self.refresh_chooser()

    def refresh_chooser(self):
        if self.chooser is not None and ida_kernwin.find_widget(CHOOSER_TITLE):
            self.chooser.Refresh()

    def show(self):
        if self.doc is None and not self.load():
            return
        if self.chooser is None:
            self.chooser = ProposalChooser(self)
        self.chooser.Show()

    def rows(self, indices) -> list[Proposal]:
        return [self.proposals[i] for i in indices if 0 <= i < len(self.proposals)]

    def apply_selected(self, indices):
        selected = self.rows(indices)
        named = [p for p in selected if p.status == backend.STATUS_NAMED]
        force = False
        if named:
            answer = ida_kernwin.ask_yn(
                ida_kernwin.ASKBTN_NO,
                f"{len(named)} of the selected functions already have a name (e.g. {named[0].current_name}).\n"
                "Replace those names too?",
            )
            if answer == ida_kernwin.ASKBTN_CANCEL:
                return
            force = answer == ida_kernwin.ASKBTN_YES

        settings = backend.load_settings()
        backend.apply(selected, settings.add_comment, force_named=force)
        self.recompute()

    def apply_auto(self):
        if self.doc is None and not self.load():
            return

        settings = backend.load_settings()
        threshold = Confidence.parse(settings.min_confidence)
        selected = backend.select_for_auto_rename(self.proposals, threshold)
        if not selected:
            ida_kernwin.info(f"No function to rename at confidence {threshold.name} or higher.")
            return

        counts = ", ".join(
            f"{sum(p.confidence == c for p in selected)} {c.name}" for c in sorted(Confidence, reverse=True)
        )
        answer = ida_kernwin.ask_yn(
            ida_kernwin.ASKBTN_YES,
            f"Rename {len(selected)} functions ({counts}) from capa rule matches?\n\n"
            "Only functions with auto-generated names (sub_...) or earlier capa names are changed.\n"
            "Use 'Undo all' in the capa auto-rename list to restore the previous names.",
        )
        if answer != ida_kernwin.ASKBTN_YES:
            return

        backend.apply(selected, settings.add_comment)
        self.recompute()

    def undo(self, indices=None):
        eas = None if indices is None else [p.ea for p in self.rows(indices)]
        restored, kept = backend.undo(eas)
        if kept:
            ida_kernwin.info(f"Restored {restored} names. Kept {kept} names that were changed by hand since.")
        self.recompute()

    def settings(self):
        if edit_settings():
            self.recompute()


class ProposalChooser(ida_kernwin.Choose):
    def __init__(self, controller: RenamerController):
        super().__init__(
            CHOOSER_TITLE,
            [
                ["Address", 12 | ida_kernwin.Choose.CHCOL_EA],
                ["Current name", 24 | ida_kernwin.Choose.CHCOL_PLAIN],
                ["Proposed name", 36 | ida_kernwin.Choose.CHCOL_PLAIN],
                ["Confidence", 7 | ida_kernwin.Choose.CHCOL_PLAIN],
                ["Status", 18 | ida_kernwin.Choose.CHCOL_PLAIN],
                ["Primary rule", 40 | ida_kernwin.Choose.CHCOL_PLAIN],
                ["Other rules", 50 | ida_kernwin.Choose.CHCOL_PLAIN],
                ["Why", 50 | ida_kernwin.Choose.CHCOL_PLAIN],
            ],
            flags=ida_kernwin.Choose.CH_MULTI | ida_kernwin.Choose.CH_CAN_REFRESH,
        )
        self.controller = controller

    def OnGetSize(self):
        return len(self.controller.proposals)

    def OnGetLine(self, n):
        p = self.controller.proposals[n]
        return [
            f"{p.ea:#x}",
            p.current_name,
            p.name or "",
            p.confidence.name,
            p.status,
            p.primary.rule,
            ", ".join(p.other_rules),
            "; ".join(p.reasons),
        ]

    def OnGetEA(self, n):
        return self.controller.proposals[n].ea

    def OnGetLineAttr(self, n):
        p = self.controller.proposals[n]
        if not p.eligible:
            # theme independent: gray out rows that will not be renamed
            return [idc.DEFCOLOR, ida_kernwin.CHITEM_GRAY]
        return None

    def OnSelectLine(self, sel):
        try:
            # CH_MULTI passes the selection as a vector of indices
            n = sel[0]
        except TypeError:
            n = sel
        if 0 <= n < len(self.controller.proposals):
            ida_kernwin.jumpto(self.controller.proposals[n].ea)

    def OnRefresh(self, n):
        return [ida_kernwin.Choose.ALL_CHANGED] + self.adjust_last_item(n)

    def OnClose(self):
        self.controller.chooser = None


class SettingsForm(ida_kernwin.Form):
    STYLES = [s.value for s in NameStyle]
    CONFIDENCES = [c.name for c in sorted(Confidence, reverse=True)]

    def __init__(self, settings: backend.RenamerSettings, rule_path: str):
        F = ida_kernwin.Form
        super().__init__(
            r"""STARTITEM 0
BUTTON YES* OK
BUTTON CANCEL Cancel
capa auto-rename settings

<capa rules directory           :{rule_path}>
<Name prefix                    :{prefix}>
<Name style                     :{style}>
<Maximum name length            :{max_length}>
<Auto-rename minimum confidence :{min_confidence}>
<Large function: basic blocks (0 = off):{big_function_bbs}>
<Large function: calls (0 = off):{big_function_calls}>
<Rule name overrides (YAML/JSON):{overrides_path}>

<Add a function comment with the matched rules:{add_comment}>
<Also rename functions that already have a name:{overwrite_named}>{options}>
""",
            {
                "rule_path": F.DirInput(value=rule_path, swidth=50),
                "prefix": F.StringInput(value=settings.prefix, swidth=20),
                "style": F.DropdownListControl(
                    items=self.STYLES, readonly=True, selval=self._index(self.STYLES, settings.style)
                ),
                "max_length": F.NumericInput(value=settings.max_length, tp=F.FT_DEC, swidth=8),
                "min_confidence": F.DropdownListControl(
                    items=self.CONFIDENCES,
                    readonly=True,
                    selval=self._index(self.CONFIDENCES, settings.min_confidence),
                ),
                "big_function_bbs": F.NumericInput(value=settings.big_function_bbs, tp=F.FT_DEC, swidth=8),
                "big_function_calls": F.NumericInput(value=settings.big_function_calls, tp=F.FT_DEC, swidth=8),
                "overrides_path": F.FileInput(open=True, value=settings.overrides_path, swidth=50),
                "options": F.ChkGroupControl(("add_comment", "overwrite_named")),
            },
        )

    @staticmethod
    def _index(items: list[str], value: str) -> int:
        return items.index(value) if value in items else 0


def edit_settings() -> bool:
    settings = backend.load_settings()
    form = SettingsForm(settings, backend.get_rule_path())
    form.Compile()
    form.add_comment.checked = settings.add_comment
    form.overwrite_named.checked = settings.overwrite_named

    try:
        if form.Execute() != 1:
            return False

        settings.prefix = form.prefix.value
        settings.style = SettingsForm.STYLES[form.style.value]
        settings.max_length = int(form.max_length.value)
        settings.min_confidence = SettingsForm.CONFIDENCES[form.min_confidence.value]
        settings.big_function_bbs = int(form.big_function_bbs.value)
        settings.big_function_calls = int(form.big_function_calls.value)
        settings.overrides_path = form.overrides_path.value
        settings.add_comment = bool(form.add_comment.checked)
        settings.overwrite_named = bool(form.overwrite_named.checked)
        rule_path = form.rule_path.value
    finally:
        form.Free()

    try:
        # fail early on a broken override file rather than on the next rename
        settings.overrides()
    except Exception as e:
        ida_kernwin.warning(f"Cannot load rule name overrides from {settings.overrides_path}:\n{e}")
        return False

    backend.save_settings(settings)
    if rule_path != backend.get_rule_path():
        backend.set_rule_path(rule_path)
    return True


class _Handler(ida_kernwin.action_handler_t):
    def __init__(self, callback, needs_chooser: bool = False, uses_selection: bool = False):
        super().__init__()
        self.callback = callback
        self.needs_chooser = needs_chooser
        self.uses_selection = uses_selection

    def activate(self, ctx):
        if self.uses_selection:
            self.callback(list(ctx.chooser_selection))
        else:
            self.callback()
        return 1

    def update(self, ctx):
        if not self.needs_chooser:
            return ida_kernwin.AST_ENABLE_ALWAYS
        if ctx.widget_type == ida_kernwin.BWN_CHOOSER and ida_kernwin.get_widget_title(ctx.widget) == CHOOSER_TITLE:
            return ida_kernwin.AST_ENABLE_FOR_WIDGET
        return ida_kernwin.AST_DISABLE_FOR_WIDGET


class _PopupHook(ida_kernwin.UI_Hooks):
    def __init__(self, popup_actions: list[str]):
        super().__init__()
        self.popup_actions = popup_actions

    def finish_populating_widget_popup(self, widget, popup, ctx=None):
        if ida_kernwin.get_widget_title(widget) != CHOOSER_TITLE:
            return
        for name in self.popup_actions:
            ida_kernwin.attach_action_to_popup(widget, popup, name, None)


class CapaRenamerPlugin(idaapi.plugin_t):
    PLUGIN_NAME = "FLARE capa auto-rename"

    wanted_name = PLUGIN_NAME
    wanted_hotkey = "Alt-Shift-F5"
    comment = "Rename functions from capa rule matches."
    help = "Preview and apply function names derived from capa rule matches."
    flags = idaapi.PLUGIN_KEEP

    def __init__(self):
        self.controller: RenamerController | None = None
        self.popup_hook: _PopupHook | None = None
        self.actions: list[str] = []

    def init(self):
        logging.basicConfig(level=logging.INFO)

        if not idaapi.is_idaq():
            # in idat/idalib use capa_rename.ida_backend directly
            return idaapi.PLUGIN_SKIP
        if not capa.ida.helpers.is_supported_ida_version():
            return idaapi.PLUGIN_SKIP
        if not capa.ida.helpers.is_supported_file_type():
            return idaapi.PLUGIN_SKIP
        if not capa.ida.helpers.is_supported_arch_type():
            return idaapi.PLUGIN_SKIP

        self.controller = RenamerController()
        self.register_actions()
        return idaapi.PLUGIN_KEEP

    def register_actions(self):
        c = self.controller
        assert c is not None

        # (name, label, handler, shortcut, attach to Edit/Plugins menu)
        definitions = [
            ("apply_selected", "Rename selected", _Handler(c.apply_selected, True, True), "Ctrl-Enter", False),
            ("apply_auto", "capa auto-rename: rename all >= min confidence", _Handler(c.apply_auto), None, True),
            ("undo_selected", "Undo selected", _Handler(c.undo, True, True), None, False),
            ("undo_all", "capa auto-rename: undo all", _Handler(lambda: c.undo(None)), None, True),
            ("reanalyze", "Re-run capa", _Handler(lambda: c.load(reanalyze=True), True), None, False),
            ("settings", "capa auto-rename: settings", _Handler(c.settings), None, True),
        ]

        for name, label, handler, shortcut, in_menu in definitions:
            action = ACTION_PREFIX + name
            if not ida_kernwin.register_action(ida_kernwin.action_desc_t(action, label, handler, shortcut)):
                logger.warning("failed to register action %s", action)
                continue
            self.actions.append(action)
            if in_menu:
                ida_kernwin.attach_action_to_menu("Edit/Plugins/", action, ida_kernwin.SETMENU_APP)

        self.popup_hook = _PopupHook(self.actions)
        self.popup_hook.hook()

    def term(self):
        if self.popup_hook is not None:
            self.popup_hook.unhook()
            self.popup_hook = None
        for action in self.actions:
            ida_kernwin.unregister_action(action)
        self.actions = []

    def run(self, arg):
        if self.controller is not None:
            self.controller.show()
        return True
