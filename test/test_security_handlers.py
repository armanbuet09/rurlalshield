"""Offline AWS-boundary tests; no boto3 installation or credentials required."""
import importlib.util
import json
import os
from pathlib import Path
import sys
import types
import unittest
from unittest.mock import Mock, patch
from urllib.parse import parse_qs, urlparse

ROOT = Path(__file__).resolve().parents[1] / "src" / "lambda"


class ClientError(Exception):
    def __init__(self, code):
        self.response = {"Error": {"Code": code}}


class Secrets:
    def __init__(self):
        self.current = "a" * 32
        self.values = {self.current: "old-signing-key-" * 4}
        self.stages = {self.current: ["AWSCURRENT"]}
        self.puts = 0

    def describe_secret(self, **kwargs):
        return {"RotationEnabled": True, "VersionIdsToStages": self.stages}

    def get_secret_value(self, **kwargs):
        version = kwargs.get("VersionId", self.current)
        if version not in self.values:
            raise ClientError("ResourceNotFoundException")
        if "VersionStage" in kwargs and kwargs["VersionStage"] not in self.stages[version]:
            raise ClientError("ResourceNotFoundException")
        return {"SecretString": self.values[version], "VersionId": version}

    def put_secret_value(self, **kwargs):
        self.puts += 1
        self.values[kwargs["ClientRequestToken"]] = kwargs["SecretString"]

    def update_secret_version_stage(self, **kwargs):
        self.stages[self.current] = ["AWSPREVIOUS"]
        self.current = kwargs["MoveToVersionId"]
        self.stages[self.current] = ["AWSCURRENT"]


class SecurityHandlers(unittest.TestCase):
    def setUp(self):
        self.secrets = Secrets()
        self.table, self.sns, self.sfn, self.s3 = Mock(), Mock(), Mock(), Mock()
        self.rows = {}
        self.table.put_item.side_effect = lambda Item: self.rows.update({(Item["pk"], Item["sk"]): Item})
        self.table.get_item.side_effect = lambda Key, **kw: {"Item": self.rows.get((Key["pk"], Key["sk"]), {}).copy()}
        self.table.update_item.side_effect = self.decide
        boto = types.ModuleType("boto3")
        boto.resource = Mock(return_value=Mock(Table=Mock(return_value=self.table)))
        clients = {"secretsmanager": self.secrets, "sns": self.sns, "stepfunctions": self.sfn, "s3": self.s3}
        boto.client = lambda service: clients[service]
        errors = types.ModuleType("botocore.exceptions")
        errors.ClientError = ClientError
        self.modules = patch.dict(sys.modules, {"boto3": boto, "botocore": types.ModuleType("botocore"), "botocore.exceptions": errors})
        self.modules.start()
        self.addCleanup(self.modules.stop)
        env = patch.dict(os.environ, INCIDENTS_TABLE="incidents", ALERTS_TOPIC_ARN="topic",
                         SIGNING_SECRET_ARN="secret", APPROVAL_BASE_URL="https://example.org/",
                         SOURCE_BUCKET="delivery", ARCHIVE_BUCKET="archive", ORG_NAME="<test>")
        env.start()
        self.addCleanup(env.stop)
        self.request = self.load("approval_request")
        self.api = self.load("approval_api")
        self.rotation = self.load("rotate_approval_secret")
        self.archive = self.load("archive_logs")

    def load(self, name):
        spec = importlib.util.spec_from_file_location(name, ROOT / name / "handler.py")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module

    def decide(self, Key, ExpressionAttributeValues, **kwargs):
        row = self.rows[(Key["pk"], Key["sk"])]
        if row["status"] != "PENDING" or row["expires_at"] <= ExpressionAttributeValues[":now"]:
            raise ClientError("ConditionalCheckFailedException")
        row["status"] = "DECIDED"
        return {"Attributes": row.copy()}

    def request_link(self):
        self.request.lambda_handler({"taskToken": "private-task-token", "incident": {"triage": {"incident_id": "one", "playbook": "<script>"}}}, None)
        message = self.sns.publish.call_args.kwargs["Message"]
        url = next(line for line in message.splitlines() if "action=approve" in line)
        return {key: value[0] for key, value in parse_qs(urlparse(url).query).items()}

    def rotate(self):
        token = "b" * 32
        self.secrets.stages[token] = ["AWSPENDING"]
        for step in ("createSecret", "setSecret", "testSecret", "finishSecret"):
            event = {"SecretId": "secret", "ClientRequestToken": token, "Step": step, "RotationToken": "rotation-token"}
            self.rotation.lambda_handler(event, None)
            self.rotation.lambda_handler(event, None)  # Retry every stage.

    def test_rotation_preserves_pending_link_and_blocks_replay(self):
        qs = self.request_link()
        self.rotate()
        response = self.api.lambda_handler({"queryStringParameters": qs}, None)
        self.assertEqual(200, response["statusCode"])
        self.assertIn("&lt;script&gt;", response["body"])
        self.assertNotIn("<script>", response["body"])
        self.assertEqual(410, self.api.lambda_handler({"queryStringParameters": qs}, None)["statusCode"])
        self.sfn.send_task_success.assert_called_once()
        self.assertTrue(json.loads(self.sfn.send_task_success.call_args.kwargs["output"])["approved"])
        self.assertEqual(1, self.secrets.puts)

    def test_warm_request_uses_new_current_key(self):
        first = self.request_link()
        self.rotate()
        second = self.request_link()
        old = self.rows[(f"APPROVAL#{first['id']}", "REQUEST")]
        new = self.rows[(f"APPROVAL#{second['id']}", "REQUEST")]
        self.assertNotEqual(old["signing_key_version"], new["signing_key_version"])
        self.assertEqual(200, self.api.lambda_handler({"queryStringParameters": second}, None)["statusCode"])

    def test_tampered_action_cannot_resume_workflow(self):
        qs = self.request_link()
        qs["action"] = "deny"
        self.assertEqual(403, self.api.lambda_handler({"queryStringParameters": qs}, None)["statusCode"])
        self.sfn.send_task_success.assert_not_called()
        self.table.update_item.assert_not_called()

    def test_expired_link_cannot_resume_workflow(self):
        qs = self.request_link()
        self.rows[(f"APPROVAL#{qs['id']}", "REQUEST")]["expires_at"] = "2000-01-01T00:00:00+00:00"
        self.assertEqual(410, self.api.lambda_handler({"queryStringParameters": qs}, None)["statusCode"])
        self.sfn.send_task_success.assert_not_called()

    def test_rotation_rejects_wrong_secret_and_unstaged_token(self):
        for secret, token in (("other", "b" * 32), ("secret", "unknown")):
            with self.assertRaises(ValueError):
                self.rotation.lambda_handler({"SecretId": secret, "ClientRequestToken": token, "Step": "createSecret"}, None)
        self.assertEqual(0, self.secrets.puts)

    def test_archiver_copies_exact_version_and_retries_to_same_key(self):
        event = {"Records": [{"s3": {"bucket": {"name": "delivery"}, "object": {"key": "logs%2Fsome+file.gz", "versionId": "v+1"}}}]}
        self.archive.lambda_handler(event, None)
        self.archive.lambda_handler(event, None)
        first, second = self.s3.copy_object.call_args_list
        self.assertEqual(first, second)
        self.assertEqual("delivery/logs/some%20file.gz?versionId=v%2B1", first.kwargs["CopySource"])
        self.assertEqual("archive", first.kwargs["Bucket"])
        self.assertNotIn("ServerSideEncryption", first.kwargs)  # Use destination CMK default.
        self.s3.delete_object.assert_not_called()

    def test_archiver_rejects_unversioned_objects(self):
        with self.assertRaises(ValueError):
            self.archive.lambda_handler({"Records": [{"s3": {"bucket": {"name": "delivery"}, "object": {"key": "one"}}}]}, None)
        self.s3.copy_object.assert_not_called()


if __name__ == "__main__":
    unittest.main()
