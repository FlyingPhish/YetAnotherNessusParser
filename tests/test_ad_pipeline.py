import json
import tempfile
import unittest
import zipfile
from pathlib import Path

from yapp.core.ad_excel import ADExcelFormatter
from yapp.core.ad_excel_operator import _fleet_access_rows
from yapp.core.ad_pipeline import analyze_bloodhound


class ADPipelineTests(unittest.TestCase):
    def test_operator_json_and_excel_are_emitted_without_path_backend(self):
        payloads = {
            "users.json": {
                "meta": {"type": "users"},
                "data": [{
                    "ObjectIdentifier": "U1",
                    "Properties": {
                        "name": "alice@corp.local",
                        "enabled": True,
                        "passwordnotrequired": True,
                    },
                }],
            },
            "computers.json": {
                "meta": {"type": "computers"},
                "data": [{
                    "ObjectIdentifier": "C1",
                    "Properties": {
                        "name": "ws1.corp.local",
                        "enabled": True,
                        "haslaps": False,
                    },
                    "LocalAdmins": {"Results": [{"ObjectIdentifier": "U1"}]},
                    "Sessions": {"Results": []},
                }],
            },
        }
        with tempfile.TemporaryDirectory() as directory:
            collection = Path(directory) / "bloodhound.zip"
            with zipfile.ZipFile(collection, "w") as archive:
                for filename, payload in payloads.items():
                    archive.writestr(filename, json.dumps(payload))
            report = analyze_bloodhound(collection)

        serialized = json.dumps(report)
        self.assertIn("operator_analysis", report)
        self.assertIn("path_analysis", report)
        self.assertIn("fleet_access", report["operator_analysis"])
        self.assertIn('"sessions", "status": "collected"', serialized)

        rows = _fleet_access_rows(report["operator_analysis"]["fleet_access"])
        self.assertIs(iter(rows), rows)
        self.assertEqual("AdminTo", next(rows)[1])

        workbook = ADExcelFormatter().format(report)
        self.assertEqual(
            ["Summary", "Risk Register", "Fleet Access", "Collection Coverage"],
            workbook.sheetnames,
        )
        self.assertTrue({
            "Findings", "Affected Entities", "Evidence", "Account Inventory",
            "Path Steps",
        }.isdisjoint(workbook.sheetnames))
        risk_sheet = workbook["Risk Register"]
        self.assertEqual("Risk ID", risk_sheet["A1"].value)
        self.assertEqual("high", risk_sheet["C2"].value)
        fleet_sheet = workbook["Fleet Access"]
        self.assertEqual("AdminTo", fleet_sheet["E2"].value)
        self.assertEqual("top", fleet_sheet["E2"].alignment.vertical)


if __name__ == "__main__":
    unittest.main()
