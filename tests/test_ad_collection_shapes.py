import json
import tempfile
import unittest
import zipfile
from pathlib import Path

from yapp.core.ad_analyzer import load_bloodhound_zip


class CollectionShapeTests(unittest.TestCase):
    def test_modern_result_wrappers_map_control_relationships(self):
        users = {
            "meta": {"type": "users"},
            "data": [
                {
                    "ObjectIdentifier": "U1",
                    "Properties": {"name": "alice@corp.local"},
                    "AllowedToDelegate": [{"ObjectIdentifier": "C1"}],
                }
            ],
        }
        computers = {
            "meta": {"type": "computers"},
            "data": [
                {
                    "ObjectIdentifier": "C1",
                    "Properties": {"name": "server01.corp.local"},
                    "LocalAdmins": {"Results": [{"ObjectIdentifier": "U1"}]},
                    "RemoteDesktopUsers": {
                        "Results": [{"ObjectIdentifier": "U2"}]
                    },
                    "PSRemoteUsers": {"Results": [{"ObjectIdentifier": "U3"}]},
                    "DcomUsers": {"Results": [{"ObjectIdentifier": "U4"}]},
                    "Sessions": {
                        "Results": [{"ComputerSID": "C1", "UserSID": "U5"}]
                    },
                    "AllowedToAct": {"Results": [{"ObjectIdentifier": "U6"}]},
                }
            ],
        }

        with tempfile.TemporaryDirectory() as directory:
            archive_path = Path(directory) / "collection.zip"
            with zipfile.ZipFile(archive_path, "w") as archive:
                archive.writestr("users.json", json.dumps(users))
                archive.writestr("computers.json", json.dumps(computers))
            graph = load_bloodhound_zip(archive_path)

        relationships = {
            (edge.source, edge.target, edge.kind) for edge in graph.edges
        }
        self.assertIn(("U1", "C1", "AdminTo"), relationships)
        self.assertIn(("U2", "C1", "CanRDP"), relationships)
        self.assertIn(("U3", "C1", "CanPSRemote"), relationships)
        self.assertIn(("U4", "C1", "ExecuteDCOM"), relationships)
        self.assertIn(("C1", "U5", "HasSession"), relationships)
        self.assertIn(("U1", "C1", "AllowedToDelegate"), relationships)
        self.assertIn(("U6", "C1", "AllowedToAct"), relationships)


if __name__ == "__main__":
    unittest.main()
