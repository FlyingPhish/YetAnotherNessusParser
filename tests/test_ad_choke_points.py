import unittest

from yapp.core.ad_choke_points import summarize_choke_points


class ADChokePointTests(unittest.TestCase):
    def test_counts_reused_steps_per_domain_and_target_class(self):
        paths = [
            {
                "source": {"id": source, "type": "User", "name": f"{source}@CORP.LOCAL"},
                "target": {"id": "DA", "type": "Group", "name": "Domain Admins@CORP.LOCAL"},
                "nodes": [
                    {"id": source, "type": "User", "name": source},
                    {"id": "G1", "type": "Group", "name": "Helpdesk@CORP.LOCAL"},
                    {"id": "DA", "type": "Group", "name": "Domain Admins@CORP.LOCAL"},
                ],
                "edges": ["MemberOf", "GenericAll"],
            }
            for source in ("U1", "U2")
        ]
        paths.append({
            "source": {"id": "U3", "type": "User", "name": "U3@OTHER.LOCAL"},
            "target": {"id": "D2", "type": "Domain", "name": "OTHER.LOCAL"},
            "nodes": [
                {"id": "U3", "type": "User", "name": "U3"},
                {"id": "D2", "type": "Domain", "name": "OTHER.LOCAL"},
            ],
            "edges": ["DCSync"],
        })

        rows = summarize_choke_points(paths)

        self.assertEqual(1, len(rows))
        self.assertEqual("CORP.LOCAL", rows[0]["domain"])
        self.assertEqual("domain_admin", rows[0]["target_class"])
        self.assertEqual("GenericAll", rows[0]["relationship"])
        self.assertEqual(2, rows[0]["path_count"])
        self.assertEqual(2, rows[0]["distinct_source_count"])


if __name__ == "__main__":
    unittest.main()
