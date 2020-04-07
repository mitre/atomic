import json
import glob
import hashlib
import logging
import os
import re

from subprocess import DEVNULL, STDOUT, check_call

from app.objects.c_ability import Ability
from app.utility.base_world import BaseWorld

name = 'Atomic'
description = 'The collection of abilities in the Red Canary Atomic test project'
address = None
access = BaseWorld.Access.RED

PLATFORMS = dict(windows='windows', macos='darwin', linux='linux')
EXECUTORS = dict(command_prompt='cmd', sh='sh', powershell='psh', bash='sh')
RE_VARIABLE = re.compile('(#{(.*?)})', re.DOTALL)


async def enable(services):
    data_svc = services.get('data_svc')
    repo_dir = 'plugins/atomic/atomic-red-team/'
    if not os.path.exists(repo_dir) or not os.listdir(repo_dir):
        repo_url = 'https://github.com/redcanaryco/atomic-red-team.git'
        check_call(['git', 'clone', '--depth', '1', repo_url, repo_dir], stdout=DEVNULL, stderr=STDOUT)

    at_ingested = 0
    at_total = 0
    errors = 0
    for filename in glob.iglob('plugins/atomic/atomic-red-team/atomics/**/T*.yaml', recursive=True):
        for entries in BaseWorld.strip_yml(filename):
            for test in entries['atomic_tests']:
                try:
                    incr_ingested, incr_total = await _save_ability(data_svc, entries, test)
                    at_ingested += incr_ingested
                    at_total += incr_total
                except Exception as e:
                    logging.debug("ERROR:", filename, e)
                    errors += 1
                    pass
    errors_output = f" and ran into {errors} errors" if errors else ""
    logging.debug(f'Ingested {at_ingested} abilities (out of {at_total}) from Atomic plugin{errors_output}')


async def _use_default_inputs(test, string):
    defaults = {key: str(val["default"]) for key, val in test.get("input_arguments", {}).items()}
    while RE_VARIABLE.search(string):
        full_string, varname = RE_VARIABLE.search(string).groups()
        string = string.replace(full_string, defaults[varname])

    return string


async def _save_ability(data_svc, entries, test):
    ability_id = hashlib.md5(json.dumps(test).encode()).hexdigest()
    at_ingested = 0
    at_total = 0
    for p in test['supported_platforms']:
        at_total += 1
        if test['executor']['name'] == 'manual':
            # this test is expected to be run manually by a human, no automation is provided
            continue
        encoded_command = BaseWorld.encode_string(await _use_default_inputs(test, test['executor']['command']))
        encoded_cleanup = BaseWorld.encode_string(await _use_default_inputs(test, test['executor'].get('cleanup_command', '')))
        await data_svc.store(
            Ability(ability_id=ability_id, tactic='redcanary', technique_id=entries['attack_technique'],
                    technique=entries['display_name'], name=test['name'], description=test['description'],
                    platform=PLATFORMS.get(p, 'unknown'), executor=EXECUTORS.get(test['executor']['name'], 'unknown'),
                    test=encoded_command, cleanup=encoded_cleanup, requirements=[], parsers=[], variations=[])
        )
        at_ingested += 1

    return (at_ingested, at_total)
