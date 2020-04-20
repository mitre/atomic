import os

from app.objects.c_plugin import Plugin
from app.utility.base_world import BaseWorld
from plugins.atomic.app.atomic_svc import AtomicService

name = 'Atomic'
description = 'The collection of abilities in the Red Canary Atomic test project'
address = None
access = BaseWorld.Access.RED

DATA_DIR = os.path.join('plugins', 'atomic', 'data')
PLUGIN = Plugin(name=name, description=description, address=address, access=access, data_dir=DATA_DIR)


async def enable(services):
    # we only ingest data once, and save new abilities in the data/ folder of the plugin
    if not (os.path.exists(DATA_DIR) and os.listdir(DATA_DIR)):
        atomic_svc = AtomicService(services, PLUGIN)
        await atomic_svc.clone_atomic_red_team_repo()
        await atomic_svc.populate_data_directory()
