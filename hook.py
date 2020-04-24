import os

from app.utility.base_world import BaseWorld
from plugins.atomic.app.atomic_svc import AtomicService

name = 'Atomic'
description = 'The collection of abilities in the Red Canary Atomic test project'
address = None
access = BaseWorld.Access.RED
data_dir = os.path.join('plugins', 'atomic', 'data')


async def enable(services):
    # we only ingest data once, and save new abilities in the data/ folder of the plugin
    if "abilities" not in os.listdir(data_dir):
        atomic_svc = AtomicService()
        await atomic_svc.clone_atomic_red_team_repo()
        await atomic_svc.populate_data_directory()
