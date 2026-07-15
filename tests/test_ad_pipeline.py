import json
import tempfile
import unittest
import zipfile
from pathlib import Path

from yapp import (
    ADAnalysisPolicy,
    ADExcelFormatter,
    ADGraph,
    analyze_bloodhound,
    get_default_ad_rules_path,
    get_supported_file_types,
    load_bloodhound_zip,
)
from yapp.core.ad_excel_operator import _fleet_access_rows


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


    def test_reuses_supplied_graph_and_reports_progress(self):
        graph = ADGraph()
        graph.add_node("U1", "User", {"name": "alice@corp.local"})
        messages = []

        report = analyze_bloodhound(
            "does-not-exist.zip",
            graph=graph,
            progress=messages.append,
        )

        self.assertEqual(1, report["engine"]["node_count"])
        self.assertIn("Loaded 1 objects and 0 relationships", messages)
        self.assertEqual("Analysis complete", messages[-1])


    def test_public_library_surface_advertises_bloodhound(self):
        capabilities = get_supported_file_types()["bloodhound"]

        self.assertEqual("analyze_bloodhound", capabilities["entry_point"])
        self.assertIn("owned_analysis", capabilities["features"])
        self.assertTrue(get_default_ad_rules_path().is_file())
        self.assertTrue(callable(load_bloodhound_zip))
        self.assertIsInstance(ADAnalysisPolicy(), ADAnalysisPolicy)


if __name__ == "__main__":
    unittest.main()
