#!/usr/bin/env python3
from __future__ import annotations

import io
import os
import sys
import tarfile
import copy
import re
import xml.etree.ElementTree as ET
from datetime import datetime
from typing import List, Tuple, Set, Dict, Iterable
import logging
from pathlib import Path

logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')
logger = logging.getLogger(__name__)

HOST_TAGS = ["IPHost", "IPHostGroup", "FQDNHost", "FQDNHostGroup", "MACHost", "MACHostGroup"]
HOST_LIST_TAGS = ["IPHostList", "FQDNHostList", "HostList"]
RULE_TAG = "FirewallRule"
GROUP_TAG = "FirewallRuleGroup"

POLICY_TAGS = {
    "WebFilter": "WebFilterPolicy",
    "ApplicationControl": "ApplicationFilterPolicy",
    "IntrusionPrevention": "IntrusionPreventionPolicy",
    "ApplicationBaseQoSPolicy": "ApplicationBaseQoSPolicy",
    "WebCategoryBaseQoSPolicy": "WebCategoryBaseQoSPolicy",
    "TrafficShappingPolicy": "TrafficShapingPolicy",
}

BUILTINS = {"None", "", "All The Time"}


def find_source_tar(search_dir: str | None = None) -> str:
    if search_dir is None:
        search_dir = os.getcwd()
    candidates = [
        f for f in os.listdir(search_dir)
        if f.lower().endswith('.tar') and 'api-' in f.lower()
    ]
    if not candidates:
        sys.exit("\nKein passendes .tar-Archiv gefunden! Lege dieses Skript neben dein API-*.tar.\n")
    candidates.sort(key=lambda f: os.path.getmtime(os.path.join(search_dir, f)), reverse=True)
    return os.path.join(search_dir, candidates[0])


def load_xml_from_tar(tar_path: str) -> Tuple[ET.ElementTree, str]:
    try:
        with tarfile.open(tar_path) as tar:
            for member in tar.getmembers():
                if member.isfile() and member.name.lower().endswith('.xml'):
                    extracted = tar.extractfile(member)
                    if extracted:
                        tree = ET.parse(extracted)
                        return tree, member.name
        sys.exit("\nKeine XML-Datei im Archiv!\n")
    except (tarfile.TarError, FileNotFoundError) as err:
        sys.exit(f"Archivfehler: {err}\n")


def get_all_rule_names(tree: ET.ElementTree) -> List[str]:
    names: List[str] = []
    for r in tree.getroot().iter(RULE_TAG):
        n = r.findtext('Name', '').strip()
        if n:
            names.append(n)
    names = sorted(set(names))
    return names


def get_all_groups(tree: ET.ElementTree) -> Dict[str, List[str]]:
    root = tree.getroot()
    groups: Dict[str, List[str]] = {}
    for g in root.findall(f'.//{GROUP_TAG}'):
        gname = g.findtext('Name', '').strip()
        if not gname:
            continue
        members: List[str] = []

        spl = g.find('SecurityPolicyList')
        if spl is not None:
            for n in spl.findall('SecurityPolicy'):
                if n.text and n.text.strip():
                    members.append(n.text.strip())

        rl = g.find('RuleList')
        if rl is not None:
            for n in rl.findall('Rule'):
                if n.text and n.text.strip():
                    members.append(n.text.strip())

        seen = set()
        unique_members = []
        for m in members:
            if m not in seen:
                seen.add(m)
                unique_members.append(m)

        groups[gname] = unique_members
    return groups


def show_catalog(rule_names: List[str], groups: Dict[str, List[str]]) -> None:
    if groups:
        print(f"\nRegelgruppen ({len(groups)}):")
        for i, gname in enumerate(sorted(groups.keys()), 1):
            count = len(groups[gname])
            print(f"  G{i}: {gname}  [{count} Regeln]")
    else:
        print("\nKeine Regelgruppen gefunden.")
    if rule_names:
        print(f"\nEinzelregeln ({len(rule_names)}):")
        for i, rname in enumerate(rule_names, 1):
            print(f"  R{i}: {rname}")
    else:
        print("\nKeine Einzelregeln gefunden.")
    print()


def _expand_group_range(a: int, b: int, group_index_map: Dict[int, str]) -> Tuple[Set[str], List[str]]:
    selected: Set[str] = set()
    invalid: List[str] = []
    if a <= b:
        rng = range(a, b+1)
    else:
        rng = range(b, a+1)
    for i in rng:
        name = group_index_map.get(i)
        if name:
            selected.add(name)
        else:
            invalid.append(f"G{i}")
    return selected, invalid


def _expand_rule_range(a: int, b: int, rule_index_map: Dict[int, str]) -> Tuple[Set[str], List[str]]:
    selected: Set[str] = set()
    invalid: List[str] = []
    if a <= b:
        rng = range(a, b+1)
    else:
        rng = range(b, a+1)
    for i in rng:
        name = rule_index_map.get(i)
        if name:
            selected.add(name)
        else:
            invalid.append(f"R{i}")
    return selected, invalid


def parse_selection_extended(selection: str, rule_names: List[str], groups: Dict[str, List[str]]) -> Tuple[Set[str], Set[str], List[str]]:
    if not selection or not selection.strip():
        return set(), set(), []

    s = selection.replace('(', ' ').replace(')', ' ')

    sorted_groups = sorted(groups.keys())
    group_index_map = {i+1: sorted_groups[i] for i in range(len(sorted_groups))}
    rule_index_map  = {i+1: rule_names[i]     for i in range(len(rule_names))}

    selected_rules: Set[str] = set()
    selected_groups: Set[str] = set()
    invalid: List[str] = []

    rough_tokens = [t for t in re.split(r'[\s,;]+', s) if t]

    g_single = re.compile(r'^g(\d+)$', re.IGNORECASE)
    r_single = re.compile(r'^r(\d+)$', re.IGNORECASE)
    num_single = re.compile(r'^(\d+)$')

    g_range = re.compile(r'^g(\d+)-g?(\d+)$', re.IGNORECASE)
    r_range = re.compile(r'^r(\d+)-r?(\d+)$', re.IGNORECASE)
    num_range = re.compile(r'^(\d+)-(\d+)$')

    i = 0
    name_chunks: List[str] = []

    def flush_name_chunk():
        nonlocal name_chunks
        if not name_chunks:
            return
        name = ' '.join(name_chunks).strip()
        name_chunks = []
        if not name:
            return
        hits = False
        g_matches = [g for g in sorted_groups if name.lower() in g.lower()]
        if g_matches:
            hits = True
            for gname in g_matches:
                selected_groups.add(gname)
                for rname in groups.get(gname, []):
                    selected_rules.add(rname)
        r_matches = [r for r in rule_names if name.lower() in r.lower()]
        if r_matches:
            hits = True
            for rname in r_matches:
                selected_rules.add(rname)
        if not hits:
            invalid.append(name)

    while i < len(rough_tokens):
        tok = rough_tokens[i]

        if i+2 < len(rough_tokens) and rough_tokens[i+1] == '-':
            a, b = rough_tokens[i], rough_tokens[i+2]
            ma = g_single.match(a); mb = g_single.match(b)
            if ma and (mb or num_single.match(b)):
                flush_name_chunk()
                aidx = int(ma.group(1))
                bidx = int((mb or num_single.match(b)).group(1))
                sel, bad = _expand_group_range(aidx, bidx, group_index_map)
                for gname in sel:
                    selected_groups.add(gname)
                    for rname in groups.get(gname, []):
                        selected_rules.add(rname)
                invalid.extend(bad)
                i += 3
                continue
            ma = r_single.match(a); mb = r_single.match(b)
            if ma and (mb or num_single.match(b)):
                flush_name_chunk()
                aidx = int(ma.group(1))
                bidx = int((mb or num_single.match(b)).group(1))
                sel, bad = _expand_rule_range(aidx, bidx, rule_index_map)
                selected_rules.update(sel)
                invalid.extend(bad)
                i += 3
                continue
            if num_single.match(a) and num_single.match(b):
                flush_name_chunk()
                aidx = int(a); bidx = int(b)
                sel, bad = _expand_rule_range(aidx, bidx, rule_index_map)
                selected_rules.update(sel)
                invalid.extend(bad)
                i += 3
                continue

        mg = g_range.match(tok)
        mr = r_range.match(tok)
        mn = num_range.match(tok)
        if mg or mr or mn:
            flush_name_chunk()
            if mg:
                aidx, bidx = int(mg.group(1)), int(mg.group(2))
                sel, bad = _expand_group_range(aidx, bidx, group_index_map)
                for gname in sel:
                    selected_groups.add(gname)
                    for rname in groups.get(gname, []):
                        selected_rules.add(rname)
                invalid.extend(bad)
            elif mr:
                aidx, bidx = int(mr.group(1)), int(mr.group(2))
                sel, bad = _expand_rule_range(aidx, bidx, rule_index_map)
                selected_rules.update(sel); invalid.extend(bad)
            else:
                aidx, bidx = int(mn.group(1)), int(mn.group(2))
                sel, bad = _expand_rule_range(aidx, bidx, rule_index_map)
                selected_rules.update(sel); invalid.extend(bad)
            i += 1
            continue

        mg = g_single.match(tok)
        mr = r_single.match(tok)
        mn = num_single.match(tok)
        if mg:
            flush_name_chunk()
            idx = int(mg.group(1))
            gname = group_index_map.get(idx)
            if gname:
                selected_groups.add(gname)
                for rname in groups.get(gname, []):
                    selected_rules.add(rname)
            else:
                invalid.append(f"G{idx}")
            i += 1; continue
        if mr:
            flush_name_chunk()
            idx = int(mr.group(1))
            rname = rule_index_map.get(idx)
            if rname:
                selected_rules.add(rname)
            else:
                invalid.append(f"R{idx}")
            i += 1; continue
        if mn:
            flush_name_chunk()
            idx = int(mn.group(1))
            rname = rule_index_map.get(idx)
            if rname:
                selected_rules.add(rname)
            else:
                invalid.append(f"R{idx}")
            i += 1; continue

        name_chunks.append(tok)
        i += 1

    flush_name_chunk()

    return selected_rules, selected_groups, invalid


def _find_by_name(root: ET.Element, tag_names: Iterable[str], name: str) -> List[ET.Element]:
    results: List[ET.Element] = []
    for t in tag_names:
        for el in root.findall(f'.//{t}[Name="{name}"]'):
            results.append(el)
    return results


def _collect_hosts_recursively(root: ET.Element, names: Iterable[str]) -> Set[str]:
    to_visit = list(set([n for n in names if n not in BUILTINS]))
    seen: Set[str] = set()
    while to_visit:
        current = to_visit.pop()
        if current in seen:
            continue
        seen.add(current)
        objs = _find_by_name(root, HOST_TAGS, current)
        if not objs:
            continue
        for obj in objs:
            for lst_tag in HOST_LIST_TAGS:
                lst = obj.find(lst_tag)
                if lst is not None:
                    for ref in lst:
                        if ref.text:
                            refname = ref.text.strip()
                            if refname and refname not in seen:
                                to_visit.append(refname)
    return seen


def _collect_services_recursively(root: ET.Element, names: Iterable[str]) -> Set[str]:
    to_visit = list(set([n for n in names if n not in BUILTINS]))
    seen_services: Set[str] = set()
    seen_groups: Set[str] = set()
    while to_visit:
        current = to_visit.pop()
        if _find_by_name(root, ["Services"], current):
            seen_services.add(current)
            continue
        grp_nodes = _find_by_name(root, ["ServiceGroup"], current)
        if grp_nodes:
            seen_groups.add(current)
            for grp in grp_nodes:
                lst = grp.find("ServiceList")
                if lst is not None:
                    for ref in lst:
                        if ref.text:
                            to_visit.append(ref.text.strip())
    return seen_services.union(seen_groups)


def _collect_policies(root: ET.Element, policy_map: Dict[str, str], policy_names: Dict[str, str]) -> Dict[str, List[ET.Element]]:
    found: Dict[str, List[ET.Element]] = {}
    for field, tag in policy_map.items():
        name = policy_names.get(field)
        if not name or name in BUILTINS:
            continue
        els = _find_by_name(root, [tag], name)
        if els:
            found[tag] = els
    return found


def _prune_group_members(group_el: ET.Element, allowed_rule_names: Set[str]) -> ET.Element:
    g = copy.deepcopy(group_el)
    spl = g.find('SecurityPolicyList')
    if spl is not None:
        to_remove = []
        for n in list(spl.findall('SecurityPolicy')):
            if not (n.text and n.text.strip() in allowed_rule_names):
                to_remove.append(n)
        for n in to_remove:
            spl.remove(n)
    rl = g.find('RuleList')
    if rl is not None:
        to_remove = []
        for n in list(rl.findall('Rule')):
            if not (n.text and n.text.strip() in allowed_rule_names):
                to_remove.append(n)
        for n in to_remove:
            rl.remove(n)
    return g


def export_rules_and_groups(tree: ET.ElementTree, selected_rule_names: Iterable[str], selected_group_names: Iterable[str]) -> ET.ElementTree:
    src_root = tree.getroot()
    out_root = ET.Element(src_root.tag, src_root.attrib)

    selected_rule_names = set(selected_rule_names)
    selected_group_names = set(selected_group_names)

    if not selected_rule_names and not selected_group_names:
        raise SystemExit("Keine passenden Regeln/Gruppen gefunden.")

    selected_rules: List[ET.Element] = []
    for r in src_root.iter(RULE_TAG):
        name = r.findtext('Name', '').strip()
        if name in selected_rule_names:
            selected_rules.append(copy.deepcopy(r))

    if not selected_rules and selected_group_names:
        pass
    elif not selected_rules:
        raise SystemExit("Keine der ausgewählten Regeln existiert in der XML.")

    ref_hosts: Set[str] = set()
    ref_services: Set[str] = set()
    ref_policy_fields: Dict[str, str] = {}

    for r in selected_rules:
        np = r.find('NetworkPolicy')
        if np is None:
            continue
        for block in ('SourceNetworks', 'DestinationNetworks'):
            blk = np.find(block)
            if blk is not None:
                for n in blk:
                    if n.text:
                        ref_hosts.add(n.text.strip())

        svc_block = np.find('Services')
        if svc_block is not None:
            for s in svc_block:
                if s.text:
                    ref_services.add(s.text.strip())

        for field in POLICY_TAGS.keys():
            val = np.findtext(field, '').strip()
            if val:
                ref_policy_fields[field] = val

    all_hosts_needed = _collect_hosts_recursively(src_root, ref_hosts)

    all_services_needed = _collect_services_recursively(src_root, ref_services)

    added_host_names: Set[str] = set()
    for tag in HOST_TAGS:
        for obj in src_root.findall(f'.//{tag}'):
            name = obj.findtext('Name', '').strip()
            if name in all_hosts_needed and name not in added_host_names:
                out_root.append(copy.deepcopy(obj))
                added_host_names.add(name)

    added_service_names: Set[str] = set()
    for tag in ["Services", "ServiceGroup"]:
        for obj in src_root.findall(f'.//{tag}'):
            name = obj.findtext('Name', '').strip()
            if name in all_services_needed and name not in added_service_names:
                out_root.append(copy.deepcopy(obj))
                added_service_names.add(name)

    policies = _collect_policies(src_root, POLICY_TAGS, ref_policy_fields)
    for tag, els in policies.items():
        for el in els:
            out_root.append(copy.deepcopy(el))

    for r in selected_rules:
        out_root.append(r)

    if selected_group_names:
        for gname in selected_group_names:
            for gel in src_root.findall(f'.//{GROUP_TAG}[Name="{gname}"]'):
                pruned = _prune_group_members(gel, selected_rule_names)
                out_root.append(pruned)

    try:
        ET.indent(out_root, space="  ")
    except AttributeError:
        pass

    return ET.ElementTree(out_root)


def export_tree_to_tar(tree: ET.ElementTree, xml_name: str, output_tar: str) -> None:
    xml_bytes = ET.tostring(tree.getroot(), encoding='utf-8', xml_declaration=True)
    try:
        with tarfile.open(output_tar, 'w') as tar:
            info = tarfile.TarInfo(name=xml_name)
            info.size = len(xml_bytes)
            info.mtime = int(datetime.now().timestamp())
            tar.addfile(info, io.BytesIO(xml_bytes))
        print(f"Export erfolgreich: {output_tar}\n")
    except tarfile.TarError as err:
        sys.exit(f"Ausgabefehler: {err}\n")


def main():
    try:
        tar_path = find_source_tar()
        print(f"\nQuell-Datei: {os.path.basename(tar_path)}")
        tree, xml_member_name = load_xml_from_tar(tar_path)

        rule_names = get_all_rule_names(tree)
        groups = get_all_groups(tree)

        if not rule_names and not groups:
            sys.exit("Keine Regeln oder Gruppen in der XML gefunden.")

        show_catalog(rule_names, groups)

        sel = input("\nWähle Regeln/Gruppen: ")

        selected_rule_names, selected_group_names, invalid = parse_selection_extended(sel, rule_names, groups)

        if invalid:
            print("\nUngültige Eingaben: " + ", ".join(invalid))
            sys.exit("\nAbbruch wegen ungültiger Eingabe!\n")

        if not selected_rule_names and not selected_group_names:
            sys.exit("\nKeine gültigen Regeln/Gruppen ausgewählt!\n")

        print(f"\nAusgewählte Regeln (insgesamt {len(selected_rule_names)}):")
        for name in sorted(selected_rule_names):
            print(f"  - {name}")
        if selected_group_names:
            print(f"\nAusgewählte Gruppen (insgesamt {len(selected_group_names)}):")
            for name in sorted(selected_group_names):
                print(f"  - {name}")

        export_name = input("\nExportname: ").strip().replace(" ", "_")
        print()
        if not export_name:
            sys.exit("\nKein Exportname!\n")

        output_path = Path(f"{export_name}.tar")
        if output_path.exists():
            overwrite = input(f"\nDatei {output_path} existiert bereits. Überschreiben? (y/n): ")
            if overwrite.lower() not in ('j', 'ja', 'y', 'yes'):
                print(f"\nExport abgebrochen – Datei existiert!\n")
                sys.exit(0)

        new_tree = export_rules_and_groups(tree, selected_rule_names, selected_group_names)
        export_tree_to_tar(new_tree, xml_member_name, str(output_path))

    except KeyboardInterrupt:
        print(f"\n\nExport durch Benutzer abgebrochen!\n")
        sys.exit(1)
    except Exception as e:
        logger.error(f"\nUnerwarteter Fehler: {e}")


if __name__ == "__main__":
    main()
