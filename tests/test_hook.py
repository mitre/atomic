import os
import pytest
from unittest.mock import MagicMock, AsyncMock, patch, PropertyMock


class TestHookModuleAttributes:
    """Test module-level attributes in hook.py."""

    def test_name(self):
        import hook
        assert hook.name == 'Atomic'

    def test_description(self):
        import hook
        assert hook.description == 'The collection of abilities in the Red Canary Atomic test project'

    def test_address(self):
        import hook
        assert hook.address == '/plugin/atomic/gui'

    def test_access(self):
        import hook
        from app.utility.base_world import BaseWorld
        assert hook.access == BaseWorld.Access.RED

    def test_data_dir(self):
        import hook
        assert hook.data_dir == os.path.join('plugins', 'atomic', 'data')


class TestHookEnable:
    """Test the enable() async function."""

    @pytest.mark.asyncio
    async def test_enable_creates_gui(self):
        import hook

        mock_app = MagicMock()
        mock_app_svc = MagicMock()
        mock_app_svc.application = mock_app

        services = {
            'auth_svc': MagicMock(),
            'data_svc': MagicMock(),
            'app_svc': mock_app_svc,
        }

        with patch.object(hook, 'data_dir', '/tmp/atomic_test_hook_data'), \
             patch('os.listdir', return_value=['abilities', 'other']), \
             patch('hook.AtomicGUI') as mock_gui_cls:
            await hook.enable(services)
            mock_gui_cls.assert_called_once_with(services, hook.name, hook.description)

    @pytest.mark.asyncio
    async def test_enable_ingests_when_no_abilities(self):
        import hook

        mock_app = MagicMock()
        mock_app_svc = MagicMock()
        mock_app_svc.application = mock_app

        services = {
            'auth_svc': MagicMock(),
            'data_svc': MagicMock(),
            'app_svc': mock_app_svc,
        }

        mock_atomic_svc = MagicMock()
        mock_atomic_svc.clone_atomic_red_team_repo = AsyncMock()
        mock_atomic_svc.populate_data_directory = AsyncMock()

        with patch.object(hook, 'data_dir', '/tmp/atomic_test_hook_data'), \
             patch('os.listdir', return_value=['some_file']), \
             patch('hook.AtomicService', return_value=mock_atomic_svc), \
             patch('hook.AtomicGUI'):
            await hook.enable(services)
            mock_atomic_svc.clone_atomic_red_team_repo.assert_called_once()
            mock_atomic_svc.populate_data_directory.assert_called_once()

    @pytest.mark.asyncio
    async def test_enable_skips_ingest_when_abilities_exist(self):
        import hook

        mock_app = MagicMock()
        mock_app_svc = MagicMock()
        mock_app_svc.application = mock_app

        services = {
            'auth_svc': MagicMock(),
            'data_svc': MagicMock(),
            'app_svc': mock_app_svc,
        }

        mock_atomic_svc = MagicMock()
        mock_atomic_svc.clone_atomic_red_team_repo = AsyncMock()
        mock_atomic_svc.populate_data_directory = AsyncMock()

        with patch.object(hook, 'data_dir', '/tmp/atomic_test_hook_data'), \
             patch('os.listdir', return_value=['abilities', 'other_stuff']), \
             patch('hook.AtomicService', return_value=mock_atomic_svc) as mock_svc_cls, \
             patch('hook.AtomicGUI'):
            await hook.enable(services)
            # AtomicService should NOT be instantiated when abilities dir exists
            mock_svc_cls.assert_not_called()

    @pytest.mark.asyncio
    async def test_enable_accesses_app(self):
        """enable() should access services['app_svc'].application."""
        import hook

        mock_app = MagicMock()
        mock_app_svc = MagicMock()
        mock_application_prop = PropertyMock(return_value=mock_app)
        type(mock_app_svc).application = mock_application_prop

        services = {
            'auth_svc': MagicMock(),
            'data_svc': MagicMock(),
            'app_svc': mock_app_svc,
        }

        with patch.object(hook, 'data_dir', '/tmp/atomic_test_hook_data'), \
             patch('os.listdir', return_value=['abilities']), \
             patch('hook.AtomicGUI'):
            await hook.enable(services)
            mock_application_prop.assert_called()
