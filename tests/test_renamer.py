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

"""tests for the IDA independent parts of the capa auto-renamer (ida/renamer, package capa_rename)"""

import os
import json
from types import SimpleNamespace
from pathlib import Path

import pytest
import capa.rules
import capa.features.freeze as frz
import capa.render.result_document as rd
import capa.features.freeze.features as frzf
from capa.features.address import NO_ADDRESS, AbsoluteVirtualAddress

from capa_rename.naming import IDENT_RE, NameStyle, NamingOptions, derive_name, make_unique
from capa_rename.proposals import (
    Confidence,
    FunctionSize,
    ScoringOptions,
    assign_names,
    load_overrides,
    build_proposals,
    split_overrides,
)

# optional: a capa rules directory to check every rule name against, e.g. CAPA_RULES=E:/capa/rules
CAPA_RULES = Path(os.environ["CAPA_RULES"]) if os.environ.get("CAPA_RULES") else None


@pytest.mark.parametrize(
    "rule_name,expected",
    [
        ("hash data using SHA256", "capa_hash_data_SHA256"),
        ("check for time delay via QueryPerformanceCounter", "capa_check_time_delay_QueryPerformanceCounter"),
        ("encrypt data using HC-128 via WolfSSL", "capa_encrypt_data_HC_128_WolfSSL"),
        ("access camera in .NET on Android", "capa_access_camera"),
        ("overwrite Master Boot Record (MBR)", "capa_overwrite_Master_Boot_Record_MBR"),
        ("linked against PolarSSL/mbed TLS", "capa_linked_against_PolarSSL_mbed_TLS"),
        ("use process Doppelgänging", "capa_use_process_Doppelganging"),
        ("add user account to group", "capa_add_user_account_to_group"),
        ("create or open file", "capa_create_or_open_file"),
    ],
)
def test_derive_name(rule_name, expected):
    assert derive_name(rule_name) == expected


def test_derive_name_styles():
    assert (
        derive_name("gather ws-ftp information", NamingOptions(style=NameStyle.PASCAL)) == "capa_GatherWsFtpInformation"
    )
    assert derive_name("hash data using SHA256", NamingOptions(style=NameStyle.LOWER)) == "capa_hash_data_sha256"


def test_derive_name_without_prefix_is_still_an_identifier():
    options = NamingOptions(prefix="")
    # cannot start with a digit
    assert derive_name("64-bit execution via heavens gate", options) == "_64_bit_execution_heavens_gate"
    # C keyword
    assert derive_name("delete", options) == "delete_"
    # looks like an IDA dummy name (sub_/unk_ followed by hex digits)
    assert derive_name("unk add", options) == "unk_add_"


def test_derive_name_override():
    assert derive_name("encrypt data using RC4 PRGA", override="rc4 crypt") == "capa_rc4_crypt"
    assert derive_name("encrypt data using RC4 PRGA", override="rc4-crypt!") == "capa_rc4_crypt"


def test_derive_name_max_length():
    name = derive_name("inject shellcode using thread pool work insertion with TP_TIMER", NamingOptions(max_length=32))
    assert name is not None
    assert len(name) <= 32
    assert IDENT_RE.match(name)
    assert name.startswith("capa_inject_shellcode")


def test_derive_name_nothing_usable():
    assert derive_name("!!! ???") is None


def test_make_unique():
    taken = {"capa_x", "capa_x_2"}
    assert make_unique("capa_y", taken.__contains__) == "capa_y"
    assert make_unique("capa_x", taken.__contains__) == "capa_x_3"
    # the suffix survives truncation
    assert make_unique("a" * 20, {"a" * 20}.__contains__, max_length=20) == "a" * 18 + "_2"


@pytest.mark.skipif(CAPA_RULES is None or not CAPA_RULES.is_dir(), reason="set CAPA_RULES to a capa rules directory")
def test_derive_name_all_rules():
    import yaml

    for path in CAPA_RULES.rglob("*.yml"):
        if ".github" in path.parts:
            continue
        doc = yaml.safe_load(path.read_text(encoding="utf-8"))
        if not doc or "rule" not in doc:
            continue
        rule_name = doc["rule"]["meta"]["name"]
        for options in (NamingOptions(), NamingOptions(prefix=""), NamingOptions(style=NameStyle.PASCAL)):
            name = derive_name(rule_name, options)
            assert name is not None, rule_name
            assert IDENT_RE.match(name), (rule_name, name)
            assert len(name) <= options.max_length, (rule_name, name)


#
# proposals
#


def _match(children=(), refs=()) -> rd.Match:
    nodes = [
        rd.Match(
            success=True,
            node=rd.FeatureNode(feature=frzf.MatchFeature(match=ref)),
            children=(),
            locations=(),
            captures={},
        )
        for ref in refs
    ]
    return rd.Match(
        success=True,
        node=rd.StatementNode(statement=rd.CompoundStatement(type="and")),
        children=tuple(children) + tuple(nodes),
        locations=(),
        captures={},
    )


def _rule(name, namespace, scope, eas, refs=(), lib=False) -> rd.RuleMatches:
    meta = rd.RuleMetadata(
        name=name,
        namespace=namespace,
        authors=("test",),
        scopes=capa.rules.Scopes(static=capa.rules.Scope(scope), dynamic=None),
        attack=(),
        mbc=(),
        references=(),
        examples=(),
        description="",
        lib=lib,
        is_subscope_rule=False,
        maec=rd.MaecMetadata(),
    )
    addresses = [NO_ADDRESS] if scope == "file" else [AbsoluteVirtualAddress(ea) for ea in eas]
    return rd.RuleMatches(
        meta=meta,
        source="",
        matches=tuple((frz.Address.from_capa(a), _match(refs=refs)) for a in addresses),
    )


def _doc(*rules):
    return SimpleNamespace(rules={r.meta.name: r for r in rules})


# function starts: 0x1000 (0x1000-0x1fff), 0x2000 (0x2000-0x2fff), ...; nothing below 0x1000
def _func_start(ea):
    return None if ea < 0x1000 else ea & ~0xFFF


def _proposals(*rules, size=None, scoring=None):
    function_size = (lambda ea: size) if size is not None else None
    scoring = scoring or ScoringOptions()
    return {p.ea: p for p in build_proposals(_doc(*rules), _func_start, function_size, scoring)}


def test_proposal_single_capability_is_high():
    proposals = _proposals(_rule("hash data using SHA256", "data-manipulation/hashing/sha256", "function", [0x1000]))
    p = proposals[0x1000]
    assert p.primary.rule == "hash data using SHA256"
    assert p.confidence == Confidence.HIGH


def test_proposal_basic_block_match_attributed_to_function():
    proposals = _proposals(
        _rule("create process suspended", "host-interaction/process/create", "basic block", [0x1234, 0x1300])
    )
    assert list(proposals) == [0x1000]
    assert proposals[0x1000].primary.locations == 2


def test_proposal_ignores_file_scope_lib_and_unmapped():
    proposals = _proposals(
        _rule("packed with UPX", "anti-analysis/packer/upx", "file", []),
        _rule("contain loop", "", "function", [0x1000], lib=True),
        _rule("parse PE header", "load-code/pe", "function", [0x10]),
    )
    assert proposals == {}


def test_proposal_dependency_is_subsumed():
    proposals = _proposals(
        _rule("inject dll", "host-interaction/process/inject", "function", [0x1000], refs=["write process memory"]),
        _rule("write process memory", "host-interaction/process/inject", "function", [0x1000]),
    )
    p = proposals[0x1000]
    assert p.primary.rule == "inject dll"
    assert [c.rule for c in p.subsumed] == ["write process memory"]
    assert p.confidence == Confidence.HIGH


def test_proposal_namespace_dependency_is_subsumed():
    proposals = _proposals(
        _rule(
            "persist via Run registry key",
            "persistence/registry/run",
            "function",
            [0x1000],
            refs=["host-interaction/registry"],
        ),
        _rule("set registry value", "host-interaction/registry/create", "basic block", [0x1010]),
    )
    p = proposals[0x1000]
    assert p.primary.rule == "persist via Run registry key"
    assert p.confidence == Confidence.HIGH


def test_proposal_related_capabilities_are_medium():
    proposals = _proposals(
        _rule("encrypt data using RC4 PRGA", "data-manipulation/encryption/rc4", "function", [0x1000]),
        _rule("encrypt data using RC4 KSA", "data-manipulation/encryption/rc4", "function", [0x1000]),
    )
    assert proposals[0x1000].confidence == Confidence.MEDIUM


def test_proposal_unrelated_capabilities_are_low():
    proposals = _proposals(
        _rule("create process on Windows", "host-interaction/process/create", "basic block", [0x1000]),
        _rule("hash data using SHA256", "data-manipulation/hashing/sha256", "function", [0x1000]),
    )
    p = proposals[0x1000]
    assert p.confidence == Confidence.LOW
    # basic block evidence outranks function evidence
    assert p.primary.rule == "create process on Windows"


def test_proposal_weak_evidence():
    proposals = _proposals(
        _rule("reference AES constants", "data-manipulation/encryption/aes", "function", [0x1000, 0x2000]),
        _rule("encrypt data using AES MixColumns step", "data-manipulation/encryption/aes", "function", [0x2000]),
    )
    # weak only: LOW
    assert proposals[0x1000].confidence == Confidence.LOW
    assert proposals[0x1000].primary.rule == "reference AES constants"
    # weak evidence does not reduce confidence of a strong capability, and is never primary next to one
    assert proposals[0x2000].confidence == Confidence.HIGH
    assert proposals[0x2000].primary.rule == "encrypt data using AES MixColumns step"
    assert proposals[0x2000].other_rules == ["reference AES constants"]


@pytest.mark.parametrize(
    "size,expected",
    [
        (FunctionSize(basic_blocks=10, calls=5), Confidence.HIGH),
        # more than big_function_bbs / big_function_calls: one level
        (FunctionSize(basic_blocks=50, calls=5), Confidence.MEDIUM),
        (FunctionSize(basic_blocks=10, calls=26), Confidence.MEDIUM),
        # more than twice: two levels
        (FunctionSize(basic_blocks=100, calls=5), Confidence.LOW),
        (FunctionSize(basic_blocks=10, calls=43), Confidence.LOW),
    ],
)
def test_proposal_large_function_is_downgraded(size, expected):
    rule = _rule("hash data using SHA256", "data-manipulation/hashing/sha256", "function", [0x1000])
    assert _proposals(rule, size=size)[0x1000].confidence == expected


def test_proposal_size_check_can_be_disabled():
    rule = _rule("hash data using SHA256", "data-manipulation/hashing/sha256", "function", [0x1000])
    scoring = ScoringOptions(big_function_bbs=0, big_function_calls=0)
    size = FunctionSize(basic_blocks=500, calls=500)
    assert _proposals(rule, size=size, scoring=scoring)[0x1000].confidence == Confidence.HIGH


def test_proposal_ignored_rule():
    rules = (
        _rule("get geographical location", "collection", "function", [0x1000]),
        _rule("hash data using SHA256", "data-manipulation/hashing/sha256", "function", [0x1000, 0x2000]),
    )
    assert _proposals(*rules)[0x1000].confidence == Confidence.LOW

    proposals = _proposals(*rules, scoring=ScoringOptions(ignored_rules=frozenset({"get geographical location"})))
    assert proposals[0x1000].primary.rule == "hash data using SHA256"
    assert proposals[0x1000].confidence == Confidence.HIGH


def test_proposal_crt_time_delay_is_weak():
    # matches MSVC __security_init_cookie
    proposals = _proposals(
        _rule(
            "check for time delay via GetTickCount",
            "anti-analysis/anti-debugging/debugger-detection",
            "function",
            [0x1000],
        )
    )
    assert proposals[0x1000].confidence == Confidence.LOW


def test_assign_names_unique_and_eligible_first():
    proposals = list(
        _proposals(
            _rule("hash data using SHA256", "data-manipulation/hashing/sha256", "function", [0x1000, 0x2000, 0x3000])
        ).values()
    )
    # the first function is already named by the user: it must not take the plain name
    proposals[0].eligible = False

    # the plain name is also used elsewhere in the database
    assign_names(proposals, is_taken=lambda name, ea: name == "capa_hash_data_SHA256_2")

    names = {p.ea: p.name for p in proposals}
    assert names[0x2000] == "capa_hash_data_SHA256"
    assert names[0x3000] == "capa_hash_data_SHA256_3"
    assert names[0x1000] == "capa_hash_data_SHA256_4"


def test_assign_names_override():
    proposals = list(
        _proposals(
            _rule("encrypt data using RC4 PRGA", "data-manipulation/encryption/rc4", "function", [0x1000])
        ).values()
    )
    assign_names(proposals, NamingOptions(prefix=""), overrides={"encrypt data using RC4 PRGA": "rc4_crypt"})
    assert proposals[0].name == "rc4_crypt"


def test_load_overrides(tmp_path):
    yml = tmp_path / "map.yml"
    yml.write_text("encrypt data using RC4 PRGA: rc4_crypt\nhash data using SHA256: sha256\n", encoding="utf-8")
    assert load_overrides(yml) == {"encrypt data using RC4 PRGA": "rc4_crypt", "hash data using SHA256": "sha256"}

    js = tmp_path / "map.json"
    js.write_text(json.dumps({"a": "b"}), encoding="utf-8")
    assert load_overrides(js) == {"a": "b"}

    bad = tmp_path / "bad.yml"
    bad.write_text("- a\n- b\n", encoding="utf-8")
    with pytest.raises(ValueError):
        load_overrides(bad)


def test_split_overrides(tmp_path):
    yml = tmp_path / "map.yml"
    yml.write_text("encrypt data using RC4 PRGA: rc4_crypt\nget geographical location: null\nterminate process:\n")
    names, ignored = split_overrides(load_overrides(yml))
    assert names == {"encrypt data using RC4 PRGA": "rc4_crypt"}
    assert ignored == {"get geographical location", "terminate process"}
