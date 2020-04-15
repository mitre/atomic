import json
import glob
import hashlib
import logging
import os
import re
import shutil
import yaml

from collections import defaultdict
from subprocess import DEVNULL, STDOUT, check_call

from app.objects.c_plugin import Plugin
from app.utility.base_world import BaseWorld

name = 'Atomic'
description = 'The collection of abilities in the Red Canary Atomic test project'
address = None
access = BaseWorld.Access.RED

PLATFORMS = dict(windows='windows', macos='darwin', linux='linux')
EXECUTORS = dict(command_prompt='cmd', sh='sh', powershell='psh', bash='sh')
RE_VARIABLE = re.compile('(#{(.*?)})', re.DOTALL)

DATA_DIR = 'plugins/atomic/data/'


async def enable(services):
    # we only ingest data once, and save new abilities in the data/ folder of the plugin
    if os.path.exists(DATA_DIR) and os.listdir(DATA_DIR):
        return

    repo_dir = 'plugins/atomic/atomic-red-team/'
    if not os.path.exists(repo_dir) or not os.listdir(repo_dir):
        repo_url = 'https://github.com/redcanaryco/atomic-red-team.git'
        check_call(['git', 'clone', '--depth', '1', repo_url, repo_dir], stdout=DEVNULL, stderr=STDOUT)

    payloads_dir = 'plugins/atomic/payloads/'
    if not os.path.exists(payloads_dir):
        os.mkdir(payloads_dir)

    entreprise_attack_path = repo_dir + "atomic_red_team/enterprise-attack.json"
    # Atomic Red Team attacks don't come with the corresponding tactic (phase name)
    # so we need to create a match between techniques and tactics.
    technique_to_tactics = defaultdict(list)
    with open(entreprise_attack_path, "r") as f:
        mitre_json = json.load(f)

    for phase_name, external_id in match_tactic_technique(mitre_json):
        technique_to_tactics[external_id].append(phase_name)

    at_ingested = 0
    at_total = 0
    errors = 0
    for filename in glob.iglob('plugins/atomic/atomic-red-team/atomics/**/T*.yaml', recursive=True):
        for entries in BaseWorld.strip_yml(filename):
            for test in entries['atomic_tests']:
                try:
                    incr_ingested, incr_total = await _save_ability(technique_to_tactics, entries, test)
                    at_ingested += incr_ingested
                    at_total += incr_total
                except Exception as e:
                    logging.debug("ERROR:", filename, e)
                    errors += 1

    data_svc = services.get('data_svc')
    await data_svc.load_data(plugins=(Plugin(name=name, description=description, address=address, access=access, data_dir=DATA_DIR),))

    errors_output = f" and ran into {errors} errors" if errors else ""
    logging.debug(f'Ingested {at_ingested} abilities (out of {at_total}) from Atomic plugin{errors_output}')


def match_tactic_technique(mitre_json):
    """
    Generator parsing the json from "enterprise-attack.json",
    and returning couples (phase_name, external_id)
    """
    for obj in mitre_json.get("objects"):
        if not obj.get("type") == "attack-pattern":
            continue
        for e in obj.get("external_references"):
            if not e.get("source_name") == "mitre-attack":
                continue
            external_id = e.get("external_id")
            for kc in obj.get("kill_chain_phases"):
                if not kc.get("kill_chain_name") == "mitre-attack":
                    continue
                phase_name = kc.get("phase_name")
                yield (phase_name, external_id)


def _handle_attachments(attachment_path):
    # attachment_path must be a POSIX path
    payload_name = os.path.basename(attachment_path)
    # to avoid collisions between payloads with the same name
    payload_name = hashlib.md5(payload_name.encode()).hexdigest() + "_" + payload_name
    payloads_dir = 'plugins/atomic/payloads/'
    shutil.copyfile(attachment_path, payloads_dir+payload_name, follow_symlinks=False)
    return payload_name


def _use_default_inputs(entries, test, platform, string):
    payloads = []  # payloads induced by a variable
    repo_dir = 'plugins/atomic/atomic-red-team/'
    defaults = {key: val for key, val in test.get("input_arguments", {}).items()}
    while RE_VARIABLE.search(string):
        full_string, varname = RE_VARIABLE.search(string).groups()
        if varname not in defaults:
            # we did not find the default value of a variable
            continue
        default_var = str(defaults[varname]["default"])

        # the variable is a path and refers to something in the atomics folder,
        # possibly a payload
        if "PathToAtomicsFolder" in default_var and defaults[varname]["type"].lower() == "path":
            default_var = default_var.replace("PathToAtomicsFolder", "atomics")
            if platform == "windows":
                default_var = default_var.replace("\\", "/")
            # TODO handle folders
            if os.path.isfile(repo_dir+default_var):
                full_path_attachement = repo_dir+default_var
                default_var = _handle_attachments(full_path_attachement)
                payloads.append(default_var)

        string = string.replace(full_string, default_var)

    return string, payloads


def _handle_multiline_commands(cmd):
    return cmd.replace("\n", ";")


async def _prepare_executor(entries, test, platform):
    payloads = []

    command, new_payloads = _use_default_inputs(entries, test, platform, test['executor']['command'])
    payloads.extend(new_payloads)
    command = _handle_multiline_commands(command)

    cleanup, new_payloads = _use_default_inputs(entries, test, platform, test['executor'].get('cleanup_command', ''))
    payloads.extend(new_payloads)
    cleanup = _handle_multiline_commands(cleanup)

    # TODO handle ART local files in command
    # eg. https://github.com/redcanaryco/atomic-red-team/blob/a956d4640f9186a7bd36d16a63f6d39433af5f1d/atomics/T1022/T1022.yaml
    # eg. https://github.com/redcanaryco/atomic-red-team/blob/fa67d8f04188955ec2c3d1532d2212f26ef5e3e8/atomics/T1502/T1502.yaml
    return (command, cleanup, payloads)


async def _save_ability(technique_to_tactics, entries, test):
    ability_id = hashlib.md5(json.dumps(test).encode()).hexdigest()
    at_ingested = 0
    at_total = 0

    tactics_li = technique_to_tactics.get(entries['attack_technique'], ['redcanary-unknown'])
    if len(tactics_li) > 1:
        tactic = 'multiple'
    else:
        tactic = tactics_li[0]

    data = {
        'id': ability_id,
        'name': test['name'],
        'description': test['description'],
        'tactic': tactic,
        'technique': {
            'attack_id': entries['attack_technique'],
            'name': entries['display_name']
        },
        'platforms': {}
    }
    for p in test['supported_platforms']:
        at_total += 1
        if test['executor']['name'] == 'manual':
            # this test is expected to be run manually by a human, no automation is provided
            continue

        command, cleanup, payloads = await _prepare_executor(entries, test, p)

        executor = EXECUTORS.get(test['executor']['name'], 'unknown')
        platform = PLATFORMS.get(p, 'unknown')
        ex_dict = {'command': command}
        ex_dict['payloads'] = payloads
        ex_dict['cleanup'] = cleanup
        data['platforms'][platform] = {executor: ex_dict}

        at_ingested += 1

    if data['platforms']:  # this might be empty, if so there's nothing useful to save
        d = DATA_DIR + ('abilities/%s' % tactic)
        if not os.path.exists(d):
            os.makedirs(d)
        file_path = '%s/%s.yml' % (d, ability_id)
        with open(file_path, 'w') as f:
            f.write(yaml.dump([data]))

    return (at_ingested, at_total)
