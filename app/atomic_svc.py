import json
import glob
import hashlib
import os
import re
import shutil
import yaml

from collections import defaultdict
from subprocess import DEVNULL, STDOUT, check_call

from app.utility.base_world import BaseWorld
from app.utility.base_service import BaseService

PLATFORMS = dict(windows='windows', macos='darwin', linux='linux')
EXECUTORS = dict(command_prompt='cmd', sh='sh', powershell='psh', bash='sh')
RE_VARIABLE = re.compile('(#{(.*?)})', re.DOTALL)


class AtomicService(BaseService):
    def __init__(self, services, plugin_self):
        self.data_svc = services.get('data_svc')
        self.log = self.add_service('atomic_svc', self)
        self.technique_to_tactics = None
        self.repo_dir = os.path.join('plugins', 'atomic', 'atomic-red-team')
        self.payloads_dir = os.path.join('plugins', 'atomic', 'payloads')
        self.plugin = plugin_self

        self.at_ingested = 0
        self.at_total = 0
        self.errors = 0

    async def clone_atomic_red_team_repo(self, repo_url=None):
        if not repo_url:
            repo_url = 'https://github.com/redcanaryco/atomic-red-team.git'

        if not os.path.exists(self.repo_dir) or not os.listdir(self.repo_dir):
            check_call(['git', 'clone', '--depth', '1', repo_url, self.repo_dir], stdout=DEVNULL, stderr=STDOUT)

    async def init_payload_dir(self):
        if not os.path.exists(self.payloads_dir):
            os.mkdir(self.payloads_dir)

    async def populate_dict_techniques_tactics(self, entreprise_attack_path=None):
        self.technique_to_tactics = defaultdict(list)
        if not entreprise_attack_path:
            entreprise_attack_path = os.path.join(self.repo_dir, 'atomic_red_team', 'enterprise-attack.json')

        # Atomic Red Team attacks don't come with the corresponding tactic (phase name)
        # so we need to create a match between techniques and tactics.
        with open(entreprise_attack_path, 'r') as f:
            mitre_json = json.load(f)

        for phase_name, external_id in self.gen_match_tactic_technique(mitre_json):
            self.technique_to_tactics[external_id].append(phase_name)

    async def populate_data_directory(self, path_yaml=None):
        if not self.technique_to_tactics:
            await self.populate_dict_techniques_tactics()

        await self.init_payload_dir()

        if not path_yaml:
            path_yaml = os.path.join(self.repo_dir, 'atomics', '**', 'T*.yaml')

        for filename in glob.iglob(path_yaml):
            for entries in BaseWorld.strip_yml(filename):
                for test in entries['atomic_tests']:
                    try:
                        incr_ingested, incr_total = await self._save_ability(entries, test)
                        self.at_ingested += incr_ingested
                        self.at_total += incr_total
                    except Exception as e:
                        self.log.debug('ERROR:', filename, e)
                        self.errors += 1

        await self.data_svc.load_data(plugins=(self.plugin,))

        errors_output = f' and ran into {self.errors} errors' if self.errors else ''
        self.log.debug(f'Ingested {self.at_ingested} abilities (out of {self.at_total}) from Atomic plugin{errors_output}')

    def gen_match_tactic_technique(self, mitre_json):
        '''
        Generator parsing the json from 'enterprise-attack.json',
        and returning couples (phase_name, external_id)
        '''
        for obj in mitre_json.get('objects'):
            if not obj.get('type') == 'attack-pattern':
                continue
            for e in obj.get('external_references'):
                if not e.get('source_name') == 'mitre-attack':
                    continue
                external_id = e.get('external_id')
                for kc in obj.get('kill_chain_phases'):
                    if not kc.get('kill_chain_name') == 'mitre-attack':
                        continue
                    phase_name = kc.get('phase_name')
                    yield (phase_name, external_id)

    def _handle_attachments(self, attachment_path):
        # attachment_path must be a POSIX path
        payload_name = os.path.basename(attachment_path)
        # to avoid collisions between payloads with the same name
        payload_name = hashlib.md5(payload_name.encode()).hexdigest()[:6] + '_' + payload_name
        shutil.copyfile(attachment_path, os.path.join(self.payloads_dir, payload_name), follow_symlinks=False)
        return payload_name

    def _use_default_inputs(self, entries, test, platform, string):
        payloads = []  # payloads induced by a variable
        defaults = dict((key, val) for key, val in test.get('input_arguments', dict()).items())
        while RE_VARIABLE.search(string):
            full_string, varname = RE_VARIABLE.search(string).groups()
            if varname not in defaults:
                # we did not find the default value of a variable
                continue
            default_var = str(defaults[varname]['default'])

            # the variable is a path and refers to something in the atomics folder,
            # possibly a payload
            if 'PathToAtomicsFolder' in default_var and defaults[varname]['type'].lower() == 'path':
                default_var = default_var.replace('PathToAtomicsFolder', 'atomics')
                if platform == 'windows':
                    default_var = default_var.replace('\\', '/')
                # TODO handle folders
                full_path_attachement = os.path.join(self.repo_dir, default_var)
                if os.path.isfile(full_path_attachement):
                    default_var = self._handle_attachments(full_path_attachement)
                    payloads.append(default_var)

            string = string.replace(full_string, default_var)

        return string, payloads

    def _handle_multiline_commands(self, cmd):
        return cmd.replace('\n', ';')

    async def _prepare_executor(self, entries, test, platform):
        payloads = []

        command, new_payloads = self._use_default_inputs(entries, test, platform, test['executor']['command'])
        payloads.extend(new_payloads)
        command = self._handle_multiline_commands(command)

        cleanup, new_payloads = self._use_default_inputs(entries, test, platform, test['executor'].get('cleanup_command', ''))
        payloads.extend(new_payloads)
        cleanup = self._handle_multiline_commands(cleanup)

        # TODO handle ART local files in command
        # eg. https://github.com/redcanaryco/atomic-red-team/blob/a956d4640f9186a7bd36d16a63f6d39433af5f1d/atomics/T1022/T1022.yaml
        # eg. https://github.com/redcanaryco/atomic-red-team/blob/fa67d8f04188955ec2c3d1532d2212f26ef5e3e8/atomics/T1502/T1502.yaml
        return (command, cleanup, payloads)

    async def _save_ability(self, entries, test):
        ability_id = hashlib.md5(json.dumps(test).encode()).hexdigest()
        at_ingested = 0
        at_total = 0

        tactics_li = self.technique_to_tactics.get(entries['attack_technique'], ['redcanary-unknown'])
        tactic = 'multiple' if len(tactics_li) > 1 else tactics_li[0]

        data = dict(
            id=ability_id,
            name=test['name'],
            description=test['description'],
            tactic=tactic,
            technique=dict(
                attack_id=entries['attack_technique'],
                name=entries['display_name']
            ),
            platforms=dict()
        )
        for p in test['supported_platforms']:
            at_total += 1
            if test['executor']['name'] == 'manual':
                # this test is expected to be run manually by a human, no automation is provided
                continue

            command, cleanup, payloads = await self._prepare_executor(entries, test, p)

            executor = EXECUTORS.get(test['executor']['name'], 'unknown')
            platform = PLATFORMS.get(p, 'unknown')
            data['platforms'][platform] = dict()
            data['platforms'][platform][executor] = dict(command=command, payloads=payloads, cleanup=cleanup)

            at_ingested += 1

        if data['platforms']:  # this might be empty, if so there's nothing useful to save
            d = os.path.join(self.plugin.data_dir, 'abilities', tactic)
            if not os.path.exists(d):
                os.makedirs(d)
            file_path = os.path.join(d, '%s.yml' % ability_id)
            with open(file_path, 'w') as f:
                f.write(yaml.dump([data]))

        return (at_ingested, at_total)
