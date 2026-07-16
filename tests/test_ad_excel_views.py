import unittest

from yapp.core.ad_excel import ADExcelFormatter


def _entity(object_id, object_type, name):
    return {"id": object_id, "type": object_type, "name": name}


class ADExcelViewTests(unittest.TestCase):
    def test_workbook_uses_correlated_operator_views(self):
        computer = _entity("C1", "Computer", "svc01.corp.local")
        user = _entity("U1", "User", "alice@corp.local")
        group = _entity("G1", "Group", "Helpdesk@corp.local")
        nested = _entity("G2", "Group", "Service Desk@corp.local")
        admins = _entity("DA", "Group", "Domain Admins@corp.local")
        ca = _entity("CA1", "EnterpriseCA", "CORP-CA@corp.local")
        domain = _entity("D1", "Domain", "corp.local")

        membership_evidence = {
            "administrative_groups": [admins],
            "memberships": [{
                "group": admins,
                "membership": "transitive",
                "via": [nested],
            }],
        }
        permission = {
            "principal": group,
            "relationship": "GenericAll",
            "category": "acl_control",
            "severity": "high",
            "target": admins,
            "effective_principals": [user],
            "effective_paths": [{
                "principal": user,
                "membership": "transitive",
                "via": [nested],
            }],
        }
        session = {
            "domain": "CORP.LOCAL",
            "principal": computer,
            "relationship": "HasSession",
            "target": user,
            "privileged_user": True,
            "domain_controller": False,
        }
        adcs_access = {
            "principal": group,
            "relationship": "GenericAll",
            "target": ca,
        }
        findings = [
            {
                "id": "ad.privilege.computer_in_administrative_group",
                "severity": "critical",
                "title": "Computer account has administrative group membership",
                "description": "Computer is privileged.",
                "entities": [computer, admins],
                "evidence": [membership_evidence],
                "remediation": "Remove the membership.",
            },
            {
                "id": "ad.permissions.control_over_high_privilege",
                "severity": "high",
                "title": "Principal controls a high-privilege object",
                "description": "Group controls Domain Admins.",
                "entities": [group, admins],
                "evidence": [permission],
                "remediation": "Remove the ACE.",
            },
            {
                "id": "ad.sessions.privileged_user_on_non_dc",
                "severity": "high",
                "title": "Privileged session exposure",
                "description": "Privileged session on a server.",
                "entities": [user, computer],
                "evidence": [session],
                "remediation": "End the session.",
            },
            {
                "id": "ad.permissions.nonprivileged_admin_to_adcs",
                "severity": "critical",
                "title": "AD CS administrative exposure",
                "description": "Group controls the CA.",
                "entities": [group, ca],
                "evidence": [adcs_access],
                "remediation": "Remove the right.",
            },
        ]
        path = {
            "source": user,
            "target": domain,
            "nodes": [user, group, domain],
            "edges": ["MemberOf", "DCSync"],
            "length": 2,
        }
        report = {
            "summary": {"total": 4, "critical": 2, "high": 2},
            "engine": {"path_backend": "direct"},
            "source": {"path": "bloodhound.zip"},
            "findings": findings,
            "privilege_analysis": {
                "sensitive_group_registry": [{
                    "key": "domain_admins",
                    "names": ["domain admins"],
                    "sid_suffixes": ["-512"],
                    "classification": "tier_zero",
                    "expected_admin": True,
                }],
                "memberships": [{
                    "principal": computer,
                    "group": admins,
                    "membership": "transitive",
                    "via": [nested],
                }],
                "permissions": [permission],
                "dcsync_paths": [path],
            },
            "operator_analysis": {
                "coverage": [{
                    "feature": "sessions",
                    "status": "collected",
                    "observed": 1,
                    "applicable": 1,
                }],
                "fleet_access": [],
                "account_inventory": {},
                "delegation": [],
                "credential_access": [],
                "sessions": [session],
                "adcs": {
                    "present": True,
                    "objects": [ca],
                    "administrative_access": [adcs_access],
                },
            },
            "path_analysis": {"choke_points": []},
        }
        mapped = [
            {
                "internal_vulnerability_id": 11,
                "finding_ids": [
                    "ad.privilege.computer_in_administrative_group"
                ],
            }
        ]

        workbook = ADExcelFormatter().format(report, mapped)

        self.assertTrue({
            "Risk Register",
            "Privileged Memberships",
            "Privileged Controls",
            "Sessions",
            "AD CS",
            "Attack Paths",
            "Collection Coverage",
        }.issubset(workbook.sheetnames))
        self.assertTrue({
            "Findings", "Affected Entities", "Evidence",
            "Administrative Memberships", "Administrative Permissions",
            "Path Steps",
        }.isdisjoint(workbook.sheetnames))

        risks = workbook["Risk Register"]
        risk_rows = {
            row[3].value: row
            for row in risks.iter_rows(min_row=2)
        }
        membership_risk = risk_rows[
            "ad.privilege.computer_in_administrative_group"
        ]
        self.assertEqual(11, membership_risk[1].value)
        self.assertEqual("MemberOf", membership_risk[9].value)
        self.assertIn("transitive", membership_risk[15].value)

        memberships = workbook["Privileged Memberships"]
        self.assertEqual("Finding", memberships["B2"].value)
        self.assertEqual("critical", memberships["C2"].value)
        self.assertEqual("Service Desk@corp.local", memberships["I2"].value)

        controls = workbook["Privileged Controls"]
        self.assertEqual("alice@corp.local", controls["F2"].value)
        self.assertIn("Service Desk@corp.local", controls["H2"].value)
        self.assertEqual("GenericAll", controls["J2"].value)

        sessions = workbook["Sessions"]
        self.assertEqual("HasSession", report["operator_analysis"]["sessions"][0]["relationship"])
        self.assertEqual("Finding", sessions["B2"].value)
        self.assertEqual("svc01.corp.local", sessions["E2"].value)

        adcs = workbook["AD CS"]
        self.assertEqual("GenericAll", adcs["K2"].value)
        self.assertEqual("Finding", adcs["B2"].value)


if __name__ == "__main__":
    unittest.main()
