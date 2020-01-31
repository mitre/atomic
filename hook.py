import json
import glob
import hashlib
import logging
import os

from subprocess import DEVNULL, STDOUT, check_call

from app.objects.c_ability import Ability
from app.utility.base_world import BaseWorld

name = 'Atomic'
description = 'The collection of abilities in the Red Canary Atomic test project'
address = None

PLATFORMS = dict(windows='windows', macos='darwin', linux='linux')
EXECUTORS = dict(command_prompt='cmd', sh='sh', powershell='psh', bash='sh')


async def enable(services):
    data_svc = services.get('data_svc')
    repo_dir = 'plugins/atomic/atomic-red-team/'
    if not os.path.exists(repo_dir) or not os.listdir(repo_dir):
        repo_url = 'https://github.com/redcanaryco/atomic-red-team.git'
        check_call(['git', 'clone', '--depth', '1', repo_url, repo_dir], stdout=DEVNULL, stderr=STDOUT)

    atomic_tests = 0
    for filename in glob.iglob('plugins/atomic/atomic-red-team/atomics/**/T*.yaml', recursive=True):
        for entries in BaseWorld.strip_yml(filename):
            for test in entries['atomic_tests']:
                try:
                    await _save_ability(data_svc, entries, test)
                    atomic_tests += 1
                except Exception:
                    pass
    logging.debug('Ingested %d abilities from Atomic plugin' % atomic_tests)


async def _save_ability(data_svc, entries, test):
    ability_id = hashlib.md5(json.dumps(test).encode()).hexdigest()
    for p in test['supported_platforms']:
        encoded_command = BaseWorld.encode_string(test['executor']['command'])
        encoded_cleanup = BaseWorld.encode_string(test['executor'].get('cleanup_command'))
        await data_svc.store(
            Ability(ability_id=ability_id, tactic='redcanary', technique_id=entries['attack_technique'],
                    technique=entries['display_name'], name=test['name'], description=test['description'],
                    platform=PLATFORMS.get(p, 'unknown'), executor=EXECUTORS.get(test['executor']['name'], 'unknown'),
                    test=encoded_command, cleanup=encoded_cleanup, requirements=[], parsers=[])
        )
