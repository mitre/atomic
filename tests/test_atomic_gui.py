import logging
import pytest
from unittest.mock import MagicMock

from app.atomic_gui import AtomicGUI


class TestAtomicGUIInit:
    """Tests for AtomicGUI initialization and configuration."""

    def test_init_stores_auth_svc(self):
        services = {'auth_svc': MagicMock(), 'data_svc': MagicMock()}
        gui = AtomicGUI(services, 'TestAtomic', 'Test description')
        assert gui.auth_svc is services['auth_svc']

    def test_init_stores_data_svc(self):
        services = {'auth_svc': MagicMock(), 'data_svc': MagicMock()}
        gui = AtomicGUI(services, 'TestAtomic', 'Test description')
        assert gui.data_svc is services['data_svc']

    def test_init_creates_logger(self):
        services = {'auth_svc': MagicMock(), 'data_svc': MagicMock()}
        gui = AtomicGUI(services, 'TestAtomic', 'Test description')
        assert isinstance(gui.log, logging.Logger)
        assert gui.log.name == 'atomic_gui'

    def test_init_with_missing_services(self):
        """If services dict doesn't have keys, attributes should be None."""
        services = {}
        gui = AtomicGUI(services, 'Atomic', 'desc')
        assert gui.auth_svc is None
        assert gui.data_svc is None

    def test_init_name_description_not_stored(self):
        """AtomicGUI receives name/description but does not store them as attributes."""
        services = {'auth_svc': MagicMock(), 'data_svc': MagicMock()}
        gui = AtomicGUI(services, 'MyName', 'MyDesc')
        # name and description are passed but not stored on the instance
        assert not hasattr(gui, 'name') or gui.name != 'MyName'
        assert not hasattr(gui, 'description') or gui.description != 'MyDesc'

    def test_multiple_instances_independent(self):
        """Each instance should have its own services."""
        svc1 = {'auth_svc': MagicMock(name='auth1'), 'data_svc': MagicMock(name='data1')}
        svc2 = {'auth_svc': MagicMock(name='auth2'), 'data_svc': MagicMock(name='data2')}
        gui1 = AtomicGUI(svc1, 'A', 'a')
        gui2 = AtomicGUI(svc2, 'B', 'b')
        assert gui1.auth_svc is not gui2.auth_svc
        assert gui1.data_svc is not gui2.data_svc


class TestAtomicGUIIsBaseWorld:
    """Verify AtomicGUI inherits from BaseWorld stub."""

    def test_is_instance_of_base_class(self):
        services = {'auth_svc': MagicMock(), 'data_svc': MagicMock()}
        gui = AtomicGUI(services, 'Atomic', 'desc')
        # AtomicGUI should be an instance of the BaseWorld stub
        from app.utility.base_world import BaseWorld
        assert isinstance(gui, BaseWorld)
