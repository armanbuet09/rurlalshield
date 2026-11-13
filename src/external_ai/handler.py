"""Optional manual Lambda transport test; never deployed with the non-AI app."""
import os

import adapter
import experiment


def lambda_handler(event, context):
    if not isinstance(event, dict) or set(event) != {"case_id"} or event["case_id"] not in experiment.CASE_IDS:
        return {"status": "rejected_input", "actions_executed": 0}
    if os.environ.get("EXPERIMENT_ENABLED") != "true":
        return {"status": "disabled", "actions_executed": 0}
    import boto3
    try:
        secret = boto3.client("secretsmanager").get_secret_value(SecretId=os.environ["API_SECRET_ARN"])
        key = secret.get("SecretString", "")
        # Secret must contain only the key. No secret content enters evidence or logs.
        return experiment.evaluate(event["case_id"], key)
    except Exception:
        # Do not let SDK exception text or secret material enter CloudWatch.
        return {"status": "credential_or_execution_error", "actions_executed": 0}
