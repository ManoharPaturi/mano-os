import copy
import hashlib
import unittest

from mano_runtime.package_postconditions import database, verify


def status(name, version='1', state='install ok installed', arch='amd64'):
    return (f'Package: {name}\nStatus: {state}\nArchitecture: {arch}\n'
            f'Version: {version}\nDescription: fixture\n\n').encode()


class PackagePostconditionTests(unittest.TestCase):
    def setUp(self):
        from test_package_plans import PackageProtocolTests

        fixture = PackageProtocolTests()
        fixture.setUp()
        self.plan = copy.deepcopy(fixture.plan)
        self.before = status('bash')
        self.plan['status_sha256'] = hashlib.sha256(self.before).hexdigest()
        self.after = self.before + status('sl', self.plan['changes'][0]['candidate'], arch='amd64')

    def test_exact_installed_versions_and_unchanged_packages(self):
        proof = verify(self.before, self.after, self.plan)
        self.assertTrue(proof['all_package_versions_checked'])
        self.assertFalse(proof['execution_authority_verified'])
        self.assertFalse(proof['maintainer_effects_verified'])
        self.assertEqual(proof['changes_verified'], 1)

    def test_exit_success_cannot_replace_actual_postconditions(self):
        for after in (self.before, self.after.replace(b'Status: install ok installed',
                      b'Status: install ok half-configured'),
                      self.after + status('unapproved'),
                      self.after.replace(b'Package: bash\n', b'Package: other\n'),
                      self.after.replace(b'Version: 1\n', b'Version: 2\n', 1)):
            with self.subTest(after=after), self.assertRaises(ValueError):
                verify(self.before, after, self.plan)

    def test_duplicate_identity_and_header_ambiguity_denied(self):
        for data in (self.before * 2, self.before.replace(b'Version: 1',
                     b'Version: 1\nVersion: 2'), self.before + b'broken line\n'):
            with self.subTest(data=data), self.assertRaises(ValueError):
                database(data)

    def test_before_hash_and_version_bindings_are_exact(self):
        with self.assertRaises(ValueError):
            verify(self.before + b'\n', self.after, self.plan)
        changed = copy.deepcopy(self.plan)
        changed['changes'][0]['installed'] = 'old'
        changed['changes'][0]['operation'] = 'upgrade'
        changed['requested'][0]['installed'] = 'old'
        with self.assertRaises(ValueError):
            verify(self.before, self.after, changed)

    def test_declared_removal_may_leave_only_configuration_record(self):
        installed = self.after
        plan = copy.deepcopy(self.plan)
        plan['names'] = ['bash']
        plan['requested'] = [dict(name='bash', installed='1', candidate='1')]
        row = plan['changes'][0]
        row.update(operation='remove', installed=row['candidate'], candidate=None,
                   archive_sha256=None, download_bytes=0)
        plan['download_bytes'] = 0
        plan['status_sha256'] = hashlib.sha256(installed).hexdigest()
        verify(installed, self.before, plan)
        verify(installed, self.before + status('sl', row['installed'],
               state='deinstall ok config-files'), plan)
        with self.assertRaises(ValueError):
            verify(installed, installed, plan)
