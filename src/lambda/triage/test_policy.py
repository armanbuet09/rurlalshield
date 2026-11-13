import unittest

import policy
from policy import Finding, Target, decide, normalize_finding, rule_based_recommendation, PLAYBOOKS


def asff_event(**overrides):
    finding = {
        "Id": "arn:aws:guardduty:us-east-2:123456789012:detector/abc/finding/f1",
        "ProductArn": "arn:aws:securityhub:us-east-2::product/aws/guardduty",
        "ProductName": "GuardDuty",
        "Title": "Credentials for IAM user jdoe were exfiltrated",
        "Description": "An access key was used from an IP associated with a known threat actor.",
        "Severity": {"Label": "CRITICAL", "Normalized": 90},
        "Types": ["TTPs/UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS"],
        "Resources": [{
            "Type": "AwsIamAccessKey",
            "Id": "AWS::IAM::AccessKey:AKIAEXAMPLE1234567",
            "Details": {"AwsIamAccessKey": {"PrincipalName": "jdoe", "PrincipalType": "IAMUser", "PrincipalId": "AIDA..."}},
        }],
        "CreatedAt": "2026-10-18T12:00:00Z",
        "AwsAccountId": "123456789012",
        "Region": "us-east-2",
        "Remediation": {"Recommendation": {"Text": "Rotate the key", "Url": "https://docs.aws.amazon.com/guardduty"}},
    }
    finding.update(overrides)
    return {"source": "aws.securityhub", "detail-type": "Security Hub Findings - Imported", "detail": {"findings": [finding]}}


def guardduty_event(**overrides):
    detail = {
        "schemaVersion": "2.0",
        "id": "gd-1",
        "type": "AttackSequence:IAM/CompromisedCredentials",
        "severity": 9.5,
        "title": "Credentials of role app-role were likely compromised",
        "description": "GuardDuty correlated several signals into an attack sequence.",
        "createdAt": "2026-10-18T12:00:00Z",
        "accountId": "123456789012",
        "region": "us-east-2",
        "resource": {"resourceType": "AccessKey", "accessKeyDetails": {
            "accessKeyId": "ASIAEXAMPLE", "principalId": "AROA...", "userName": "app-role/session", "userType": "AssumedRole"}},
        "service": {"detection": {"sequence": {"signals": [{"name": "Discovery:IAMUser/AnomalousBehavior"}], "tactics": ["TA0006"]}}},
    }
    detail.update(overrides)
    return {"source": "aws.guardduty", "detail-type": "GuardDuty Finding", "detail": detail}


class NormalizationTests(unittest.TestCase):
    def test_asff_access_key(self):
        f = normalize_finding(asff_event())
        self.assertEqual(f.source, "securityhub")
        self.assertEqual(f.category, "threat")
        self.assertEqual(f.severity_label, "CRITICAL")
        self.assertEqual(f.targets[0].type, "iam-access-key")
        self.assertEqual(f.targets[0].id, "AKIAEXAMPLE1234567")
        self.assertEqual(f.targets[0].extra["user_name"], "jdoe")

    def test_asff_assumed_role_becomes_role_target(self):
        ev = asff_event(Resources=[{"Type": "AwsIamAccessKey", "Id": "AWS::IAM::AccessKey:ASIAXYZ",
                                     "Details": {"AwsIamAccessKey": {"PrincipalName": "app-role/sess", "PrincipalType": "AssumedRole"}}}])
        f = normalize_finding(ev)
        self.assertEqual(f.targets[0].type, "iam-role")
        self.assertEqual(f.targets[0].name, "app-role")

    def test_guardduty_native(self):
        f = normalize_finding(guardduty_event())
        self.assertEqual(f.source, "guardduty")
        self.assertEqual(f.severity_label, "CRITICAL")
        self.assertEqual(f.targets[0].type, "iam-role")
        self.assertIn("TA0006", f.mitre)

    def test_posture_category(self):
        ev = asff_event(ProductName="Security Hub", Types=["Software and Configuration Checks/Industry and Regulatory Standards/AWS-Foundational-Security-Best-Practices"],
                        Resources=[{"Type": "AwsS3Bucket", "Id": "arn:aws:s3:::phi-bucket"}])
        f = normalize_finding(ev)
        self.assertEqual(f.category, "posture")
        self.assertEqual(f.targets[0].type, "s3-bucket")
        self.assertEqual(f.targets[0].name, "phi-bucket")

    def test_protected_tag_detected(self):
        ev = asff_event(Resources=[{"Type": "AwsLambdaFunction", "Id": "arn:aws:lambda:us-east-2:1:function:rs-triage",
                                     "Tags": {"rural-shield:protected": "true"}}])
        f = normalize_finding(ev)
        self.assertTrue(f.targets[0].protected)

    def test_excerpt_truncates(self):
        f = normalize_finding(asff_event(Description="x" * 20000))
        self.assertLess(len(f.raw_excerpt), 6100)
        self.assertTrue(f.raw_excerpt.endswith("<truncated>"))


class RuleBasedTests(unittest.TestCase):
    def test_exfiltration_maps_to_key_deactivation(self):
        self.assertEqual(rule_based_recommendation(normalize_finding(asff_event())), "DEACTIVATE_IAM_ACCESS_KEY")

    def test_attack_sequence_maps_to_revoke_sessions(self):
        self.assertEqual(rule_based_recommendation(normalize_finding(guardduty_event())), "REVOKE_ROLE_SESSIONS")

    def test_posture_escalates_only(self):
        ev = asff_event(ProductName="Security Hub", Types=["Software and Configuration Checks/AWS Security Best Practices"])
        self.assertEqual(rule_based_recommendation(normalize_finding(ev)), "ESCALATE_ONLY")


class DecisionTests(unittest.TestCase):
    def test_auto_for_critical_reversible_with_agreement(self):
        f = normalize_finding(asff_event())
        d = decide(f, "DEACTIVATE_IAM_ACCESS_KEY", 0.92, auto_containment_enabled=True)
        self.assertEqual(d.action_mode, "AUTO")
        self.assertEqual(d.targets[0].id, "AKIAEXAMPLE1234567")

    def test_high_severity_falls_to_approval(self):
        f = normalize_finding(asff_event(Severity={"Label": "HIGH", "Normalized": 70}))
        d = decide(f, "DEACTIVATE_IAM_ACCESS_KEY", 0.92, True)
        self.assertEqual(d.action_mode, "APPROVAL")
        self.assertTrue(any("below auto threshold" in r for r in d.reasons))

    def test_low_confidence_falls_to_approval(self):
        f = normalize_finding(asff_event())
        d = decide(f, "DEACTIVATE_IAM_ACCESS_KEY", 0.4, True)
        self.assertEqual(d.action_mode, "APPROVAL")

    def test_operator_opt_out(self):
        f = normalize_finding(asff_event())
        d = decide(f, "DEACTIVATE_IAM_ACCESS_KEY", 0.95, auto_containment_enabled=False)
        self.assertEqual(d.action_mode, "APPROVAL")
        self.assertIn("operator disabled unattended containment", d.reasons)

    def test_unknown_playbook_downgrades(self):
        f = normalize_finding(asff_event())
        d = decide(f, "DELETE_EVERYTHING", 0.99, True)
        self.assertEqual(d.action_mode, "NOTIFY")
        self.assertEqual(d.playbook, "ESCALATE_ONLY")

    def test_posture_finding_never_contained(self):
        ev = asff_event(ProductName="Security Hub", Types=["Software and Configuration Checks/AWS Security Best Practices"],
                        Resources=[{"Type": "AwsS3Bucket", "Id": "arn:aws:s3:::b"}])
        d = decide(normalize_finding(ev), "BLOCK_S3_PUBLIC_ACCESS", 0.99, True)
        self.assertEqual(d.action_mode, "NOTIFY")

    def test_model_rule_disagreement_requires_human(self):
        # Model asks to quarantine a role for an exfiltrated *user* key: rules say deactivate the key.
        ev = asff_event(Resources=[
            {"Type": "AwsIamAccessKey", "Id": "AWS::IAM::AccessKey:AKIA1", "Details": {"AwsIamAccessKey": {"PrincipalName": "jdoe", "PrincipalType": "IAMUser"}}},
            {"Type": "AwsIamRole", "Id": "arn:aws:iam::1:role/some-role"},
        ])
        d = decide(normalize_finding(ev), "REVOKE_ROLE_SESSIONS", 0.95, True)
        self.assertEqual(d.action_mode, "APPROVAL")
        self.assertTrue(any("differs from rule-based" in r for r in d.reasons))

    def test_protected_target_blocks_everything(self):
        ev = asff_event(Resources=[{"Type": "AwsIamAccessKey", "Id": "AWS::IAM::AccessKey:AKIA1", "Tags": {"rural-shield:protected": "true"},
                                     "Details": {"AwsIamAccessKey": {"PrincipalName": "svc", "PrincipalType": "IAMUser"}}}])
        d = decide(normalize_finding(ev), "DEACTIVATE_IAM_ACCESS_KEY", 0.99, True)
        self.assertEqual(d.action_mode, "NOTIFY")

    def test_non_auto_playbook_always_approval(self):
        ev = guardduty_event(type="CryptoCurrency:Lambda/BitcoinTool.B", severity=8.0,
                             resource={"lambdaDetails": {"functionArn": "arn:aws:lambda:us-east-2:1:function:portal", "functionName": "portal"}})
        d = decide(normalize_finding(ev), "QUARANTINE_LAMBDA_FUNCTION", 0.9, True)
        self.assertEqual(d.action_mode, "APPROVAL")
        self.assertEqual(d.targets[0].name, "portal")

    def test_fallback_without_model(self):
        f = normalize_finding(guardduty_event())
        pb = rule_based_recommendation(f)
        d = decide(f, pb, 0.0, True, model_used=False)
        self.assertEqual(d.action_mode, "AUTO")
        self.assertEqual(d.playbook, "REVOKE_ROLE_SESSIONS")

    def test_every_playbook_is_reversible(self):
        for name, pb in PLAYBOOKS.items():
            self.assertTrue(pb["reversible"], name)


if __name__ == "__main__":
    unittest.main()
