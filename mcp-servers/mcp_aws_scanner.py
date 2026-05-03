import boto3
import json
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("AWS Security Scanner")


def get_client(service: str):
    return boto3.client(service, region_name="us-east-1")


@mcp.tool()
def audit_iam_users() -> str:
    """Audit IAM users for security risks — MFA, access keys, unused accounts."""
    try:
        iam = get_client("iam")
        users = iam.list_users()["Users"]
        results = []
        for user in users:
            username = user["UserName"]
            # Check MFA
            mfa = iam.list_mfa_devices(UserName=username)["MFADevices"]
            # Check access keys
            keys = iam.list_access_keys(UserName=username)["AccessKeyMetadata"]
            key_info = [
                {"key_id": k["AccessKeyId"][:8] + "...", "status": k["Status"]}
                for k in keys
            ]
            results.append({
                "user": username,
                "mfa_enabled": len(mfa) > 0,
                "access_keys": key_info,
                "risk": "HIGH" if not mfa and keys else "LOW"
            })
        risky = [r for r in results if r["risk"] == "HIGH"]
        return json.dumps({
            "total_users": len(results),
            "risky_users": len(risky),
            "users": results
        }, indent=2)
    except Exception as e:
        return f"IAM audit failed: {str(e)}"


@mcp.tool()
def audit_s3_buckets() -> str:
    """Audit S3 buckets for public access, encryption, and versioning."""
    try:
        s3 = get_client("s3")
        buckets = s3.list_buckets()["Buckets"]
        results = []
        for bucket in buckets:
            name = bucket["Name"]
            findings = []
            # Check public access block
            try:
                public = s3.get_public_access_block(Bucket=name)["PublicAccessBlockConfiguration"]
                if not all(public.values()):
                    findings.append("Public access not fully blocked")
            except Exception:
                findings.append("No public access block configured")
            # Check versioning
            try:
                versioning = s3.get_bucket_versioning(Bucket=name)
                if versioning.get("Status") != "Enabled":
                    findings.append("Versioning not enabled")
            except Exception:
                findings.append("Could not check versioning")
            # Check encryption
            try:
                s3.get_bucket_encryption(Bucket=name)
            except Exception:
                findings.append("Encryption not configured")

            results.append({
                "bucket": name,
                "findings": findings,
                "risk": "HIGH" if len(findings) >= 2 else "MEDIUM" if findings else "LOW"
            })
        return json.dumps({
            "total_buckets": len(results),
            "high_risk": len([r for r in results if r["risk"] == "HIGH"]),
            "buckets": results
        }, indent=2)
    except Exception as e:
        return f"S3 audit failed: {str(e)}"


@mcp.tool()
def audit_security_groups() -> str:
    """Audit EC2 security groups for overly permissive inbound rules (0.0.0.0/0)."""
    try:
        ec2 = get_client("ec2")
        sgs = ec2.describe_security_groups()["SecurityGroups"]
        results = []
        for sg in sgs:
            risky_rules = []
            for rule in sg.get("IpPermissions", []):
                for ip_range in rule.get("IpRanges", []):
                    if ip_range.get("CidrIp") == "0.0.0.0/0":
                        port = rule.get("FromPort", "ALL")
                        proto = rule.get("IpProtocol", "all")
                        risky_rules.append(f"Port {port}/{proto} open to 0.0.0.0/0")
            if risky_rules:
                results.append({
                    "group_id": sg["GroupId"],
                    "group_name": sg["GroupName"],
                    "risky_rules": risky_rules,
                    "risk": "CRITICAL" if any("22" in r or "3389" in r for r in risky_rules) else "HIGH"
                })
        return json.dumps({
            "total_risky_groups": len(results),
            "security_groups": results
        }, indent=2) if results else "No overly permissive security groups found"
    except Exception as e:
        return f"Security group audit failed: {str(e)}"


@mcp.tool()
def audit_cloudtrail() -> str:
    """Check if CloudTrail is enabled and logging in all regions."""
    try:
        ct = get_client("cloudtrail")
        trails = ct.describe_trails()["trailList"]
        results = []
        for trail in trails:
            status = ct.get_trail_status(Name=trail["TrailARN"])
            results.append({
                "trail_name": trail["Name"],
                "is_logging": status.get("IsLogging", False),
                "multi_region": trail.get("IsMultiRegionTrail", False),
                "log_validation": trail.get("LogFileValidationEnabled", False),
                "risk": "HIGH" if not status.get("IsLogging") else "LOW"
            })
        if not results:
            return json.dumps({"risk": "CRITICAL", "finding": "No CloudTrail configured"}, indent=2)
        return json.dumps({"trails": results}, indent=2)
    except Exception as e:
        return f"CloudTrail audit failed: {str(e)}"


@mcp.tool()
def get_ecs_services() -> str:
    """List running ECS services and check their security configuration."""
    try:
        ecs = get_client("ecs")
        clusters = ecs.list_clusters()["clusterArns"]
        results = []
        for cluster_arn in clusters:
            cluster_name = cluster_arn.split("/")[-1]
            services = ecs.list_services(cluster=cluster_arn)["serviceArns"]
            for service_arn in services:
                service = ecs.describe_services(
                    cluster=cluster_arn,
                    services=[service_arn]
                )["services"][0]
                results.append({
                    "cluster": cluster_name,
                    "service": service["serviceName"],
                    "status": service["status"],
                    "running_count": service["runningCount"],
                    "desired_count": service["desiredCount"],
                    "launch_type": service.get("launchType", "UNKNOWN")
                })
        return json.dumps({"ecs_services": results}, indent=2) if results else "No ECS services found"
    except Exception as e:
        return f"ECS audit failed: {str(e)}"


@mcp.tool()
def full_security_audit() -> str:
    """Run a complete AWS security audit across IAM, S3, Security Groups, and CloudTrail."""
    report = {}
    # IAM
    try:
        iam = get_client("iam")
        users = iam.list_users()["Users"]
        risky_users = 0
        for user in users:
            mfa = iam.list_mfa_devices(UserName=user["UserName"])["MFADevices"]
            keys = iam.list_access_keys(UserName=user["UserName"])["AccessKeyMetadata"]
            if not mfa and keys:
                risky_users += 1
        report["iam"] = {"total_users": len(users), "users_without_mfa": risky_users}
    except Exception as e:
        report["iam"] = {"error": str(e)}

    # S3
    try:
        s3 = get_client("s3")
        buckets = s3.list_buckets()["Buckets"]
        report["s3"] = {"total_buckets": len(buckets)}
    except Exception as e:
        report["s3"] = {"error": str(e)}

    # Security Groups
    try:
        ec2 = get_client("ec2")
        sgs = ec2.describe_security_groups()["SecurityGroups"]
        open_sgs = sum(
            1 for sg in sgs
            for rule in sg.get("IpPermissions", [])
            for ip in rule.get("IpRanges", [])
            if ip.get("CidrIp") == "0.0.0.0/0"
        )
        report["security_groups"] = {"total": len(sgs), "open_to_internet": open_sgs}
    except Exception as e:
        report["security_groups"] = {"error": str(e)}

    # CloudTrail
    try:
        ct = get_client("cloudtrail")
        trails = ct.describe_trails()["trailList"]
        report["cloudtrail"] = {"trails_configured": len(trails)}
    except Exception as e:
        report["cloudtrail"] = {"error": str(e)}

    return json.dumps({"aws_security_audit": report}, indent=2)


if __name__ == "__main__":
    mcp.run()
