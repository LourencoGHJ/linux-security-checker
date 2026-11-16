import unittest
from unittest.mock import patch
from golfinho.interface.dashboard import DashboardState, PAGE

class TestDashboardState(unittest.TestCase):
    @patch('golfinho.engine.scanner.run_security_scan')
    def test_collect_once_publishes_snapshot(self, scan):
        scan.return_value = {'platform': {'name': 'Windows 11'}, 'network': {'interfaces': []}, 'firewall': {'profiles': []}, 'findings': [], 'errors': []}
        state = DashboardState(3)
        state.collect_once()
        snapshot = state.snapshot()
        self.assertEqual(snapshot['data']['platform']['name'], 'Windows 11')
        self.assertEqual(snapshot['interval_seconds'], 3)
        self.assertIsNotNone(snapshot['updated_at'])
        self.assertIsNone(snapshot['error'])

    @patch('golfinho.engine.scanner.run_security_scan', side_effect=RuntimeError('collector failed'))
    def test_collection_error_is_exposed(self, scan):
        state = DashboardState(1)
        state.collect_once()
        self.assertEqual(state.snapshot()['error'], 'collector failed')

    def test_dashboard_contains_live_sections(self):
        for value in ('setInterval(refresh,1000)', '/api/snapshot', 'Interfaces de rede', 'Regras e filtros da firewall'):
            self.assertIn(value, PAGE)

if __name__ == '__main__':
    unittest.main()
