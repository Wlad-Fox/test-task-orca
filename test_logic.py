from unittest import TestCase
from logic import App, Machine, FirewallAllowRule, MultipleChoiceError


def create_machine(id, name=None, tags=None):
    return Machine(id, name or "unnamed", tags or [])


class AppGetMachineTest(TestCase):
    def setUp(self):
        self.app = App()
        self.app.machines = [
            create_machine('a1b2c3d4', "test with d4"),
            create_machine('a1b2c3xx', "test with x"),
            create_machine('a8888888', "eights"),
        ]

    def tearDown(self):
        pass

    def test_empty_argument_raises(self):
        with self.assertRaises(AssertionError):
            self.app._get_machine_by_id('')

    def test_wrong_id_raises_key_error(self):
        with self.assertRaises(KeyError):
            self.app._get_machine_by_id('12345678')

    def test_get_by_full_id(self):
        machine = self.app._get_machine_by_id('a8888888')
        self.assertEqual(machine.id, 'a8888888')
        self.assertEqual(machine.name, 'eights')

    def test_get_by_partial_id(self):
        machine = self.app._get_machine_by_id('a8')
        self.assertEqual(machine.id, 'a8888888')
        self.assertEqual(machine.name, 'eights')

    def test_partial_id_collision_raises(self):
        with self.assertRaises(MultipleChoiceError):
            self.app._get_machine_by_id('a1b2c3')

    def test_partially_colliding_ids_success(self):
        machine = self.app._get_machine_by_id('a1b2c3x')
        self.assertEqual(machine.id, 'a1b2c3xx')
        self.assertEqual(machine.name, 'test with x')

        machine = self.app._get_machine_by_id('a1b2c3d')
        self.assertEqual(machine.id, 'a1b2c3d4')
        self.assertEqual(machine.name, 'test with d4')

    def test_get_on_empty_raises_key_error(self):
        self.app.machines = []
        with self.assertRaises(KeyError):
            self.app._get_machine_by_id("a1b2c3d4")


class AppGetAttackVectorsTest(TestCase):
    def setUp(self):
        self.app = App()
        self.app.machines = [
            create_machine('1000', tags=["id_1000", "group_1"]),
            create_machine('1002', tags=["id_1002", "group_1"]),
            create_machine('1003', tags=["id_1003", "group_1"]),
            create_machine('1100', tags=["id_1100", "group_2"]),
            create_machine('1200', tags=["id_1200", "group_3"]),
            create_machine('1510', tags=["id_1510", "group_4"]),
            create_machine('1520', tags=[]),
        ]
        self.app.rules = [ 
            FirewallAllowRule("fw-1", "group_1", "group_1"),
            FirewallAllowRule("fw-2", "group_2", "group_1"),
            FirewallAllowRule("fw-3", "group_3", "group_1"),
            FirewallAllowRule("fw-4", "group_3", "group_2"),
            FirewallAllowRule("fw-5", "group_4", "group_1"),
            FirewallAllowRule("fw-6", "group_4", "group_2"),
            FirewallAllowRule("fw-7", "group_4", "group_3"),
            FirewallAllowRule("fw-8", "id_1000", "id_1200"),
        ]

    def tearDown(self):
        pass

    def test_colliding_ids_raises(self):
        with self.assertRaises(MultipleChoiceError):
            self.app.get_attack_vectors("1")

    def test_no_rules_returns_empty(self):
        self.app.rules = []
        self.assertEqual(self.app.get_attack_vectors("1000"), [])

    def test_untagged_machine_returns_empty(self):
        self.assertEqual(self.app.get_attack_vectors("1520"), [])

    def test_general(self):
        def vectors(id):
            return set((self.app.get_attack_vectors(id)))
        
        self.assertEqual(vectors('1000'), set(["1002", "1003", "1100", "1200", "1510"]))
        self.assertEqual(vectors('1002'), set(["1000", "1003", "1100", "1200", "1510"]))
        self.assertEqual(vectors('1003'), set(["1000", "1002", "1100", "1200", "1510"]))
        self.assertEqual(vectors('1100'), set(["1200", "1510"]))
        self.assertEqual(vectors('1200'), set(["1510", "1000"]))
        self.assertEqual(vectors('1510'), set([]))
