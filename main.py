import boto3
from botocore.exceptions import ClientError
import datetime

# --- HELPER FUNCTION (UNCHANGED) ---
def get_all_aws_regions():
    """
    Gets a list of all enabled AWS regions.
    """
    try:
        ec2_client = boto3.client('ec2')
        regions = ec2_client.describe_regions(
            Filters=[{'Name': 'opt-in-status', 'Values': ['opt-in-not-required', 'opted-in']}]
        )
        return [region['RegionName'] for region in regions['Regions']]
    except ClientError as e:
        print(f"Error getting AWS regions: {e}. Defaulting to us-east-1.")
        return ["us-east-1"]

# --- CHECK FUNCTIONS (MODIFIED WITH COMPLIANCE MAPPINGS) ---

def check_s3_public_access():
    """Checks S3 public access. (CIS 1.2.1)"""
    s3_client = boto3.client('s3')
    findings = []
    try:
        response = s3_client.list_buckets()
        buckets = response.get('Buckets', [])
        if not buckets:
            return {"status": "PASS", "check": "S3 Public Access", "details": "No S3 buckets found."}

        for bucket in buckets:
            bucket_name = bucket['Name']
            try:
                pab = s3_client.get_public_access_block(Bucket=bucket_name)
                config = pab.get('PublicAccessBlockConfiguration', {})
                if not (config.get('BlockPublicAcls', False) and
                        config.get('IgnorePublicAcls', False) and
                        config.get('BlockPublicPolicy', False) and
                        config.get('RestrictPublicBuckets', False)):
                    findings.append(f"Bucket '{bucket_name}' is not configured to block all public access.")
            except ClientError as e:
                if e.response['Error']['Code'] == 'NoSuchPublicAccessBlockConfiguration':
                    findings.append(f"Bucket '{bucket_name}' has no Public Access Block configured.")
        
        if not findings:
            return {"status": "PASS", "check": "S3 Public Access", "details": "All S3 buckets block public access."}
        else:
            # ADDED COMPLIANCE
            return {"status": "FAIL", "severity": "Critical", "check": "S3 Public Access", "details": findings, 
                    "fix": "Enable 'Block all public access' in the S3 bucket's permissions tab.",
                    "compliance": {"CIS": "1.2.1", "ISO 27001": "A.9.1.2", "NIST CSF": "PR.AC-3"}}

    except ClientError as e:
        return {"status": "ERROR", "check": "S3 Public Access", "details": f"Could not check S3: {e}"}

def check_iam_password_policy():
    """Checks IAM password policy strength. (CIS 1.5-1.8)"""
    iam_client = boto3.client('iam')
    try:
        policy = iam_client.get_account_password_policy()['PasswordPolicy']
        failures = []
        if not policy.get('RequireUppercaseCharacters', False): failures.append("does not require uppercase")
        if not policy.get('RequireLowercaseCharacters', False): failures.append("does not require lowercase")
        if not policy.get('RequireNumbers', False): failures.append("does not require numbers")
        if not policy.get('RequireSymbols', False): failures.append("does not require symbols")
        
        if not failures:
            return {"status": "PASS", "check": "IAM Password Policy", "details": "IAM password policy is strong."}
        else:
            details = f"IAM password policy is weak: {', '.join(failures)}."
            # ADDED COMPLIANCE
            return {"status": "FAIL", "severity": "Medium", "check": "IAM Password Policy", "details": [details], 
                    "fix": "Edit the IAM Account Settings password policy to require uppercase, lowercase, numbers, and symbols.",
                    "compliance": {"CIS": "1.5-1.8", "ISO 27001": "A.9.4.3", "NIST CSF": "PR.AC-1"}}
                
    except ClientError as e:
        if e.response['Error']['Code'] == 'NoSuchEntity':
            # ADDED COMPLIANCE
            return {"status": "FAIL", "severity": "Medium", "check": "IAM Password Policy", "details": ["No IAM password policy is set."], 
                    "fix": "Go to IAM > Account Settings and create a password policy.",
                    "compliance": {"CIS": "1.5-1.8", "ISO 27001": "A.9.4.3", "NIST CSF": "PR.AC-1"}}
        else:
            return {"status": "ERROR", "check": "IAM Password Policy", "details": f"Could not check IAM: {e}"}

def check_ec2_security_groups():
    """Checks EC2 Security Groups for open SSH in ALL regions. (CIS 5.1)"""
    findings = []
    regions = get_all_aws_regions()
    
    for region in regions:
        try:
            ec2_client = boto3.client('ec2', region_name=region)
            groups = ec2_client.describe_security_groups()['SecurityGroups']
            
            for group in groups:
                for rule in group.get('IpPermissions', []):
                    if rule.get('IpProtocol') == 'tcp' and rule.get('FromPort') == 22 and rule.get('ToPort') == 22:
                        for ip_range in rule.get('IpRanges', []):
                            if ip_range.get('CidrIp') == '0.0.0.0/0':
                                findings.append(f"Region '{region}': Security Group '{group['GroupId']}' allows public SSH (port 22) from 0.0.0.0/0.")
                                break
        except ClientError as e:
            if e.response['Error']['Code'] in ['AuthFailure', 'UnauthorizedOperation']:
                continue
            else:
                findings.append(f"Region '{region}': Could not scan EC2. {e}")

    if not findings:
        return {"status": "PASS", "check": "EC2 Public SSH", "details": "No security groups allow unrestricted SSH in any region."}
    else:
        # ADDED COMPLIANCE
        return {"status": "FAIL", "severity": "Critical", "check": "EC2 Public SSH", "details": findings, 
                "fix": "Remove the rule allowing 0.0.0.0/0 on port 22 from the listed security groups.",
                "compliance": {"CIS": "5.1", "ISO 27001": "A.12.1.2", "NIST CSF": "PR.AC-3"}}

def check_cloudtrail_enabled():
    """Checks for a multi-region CloudTrail. (CIS 2.1.1)"""
    cloudtrail_client = boto3.client('cloudtrail')
    try:
        trails = cloudtrail_client.describe_trails()['trailList']
        if not trails:
            # ADDED COMPLIANCE
            return {"status": "FAIL", "severity": "High", "check": "CloudTrail Enabled", "details": ["No CloudTrail trails are configured."], 
                    "fix": "Create a new CloudTrail trail and apply it to all regions.",
                    "compliance": {"CIS": "2.1.1", "ISO 27001": "A.12.4.1", "NIST CSF": "DE.CM-1"}}

        is_logging_globally = False
        for trail in trails:
            if trail.get('IsMultiRegionTrail', False):
                if cloudtrail_client.get_trail_status(Name=trail['TrailARN'])['IsLogging']:
                    is_logging_globally = True
                    break
        
        if is_logging_globally:
            return {"status": "PASS", "check": "CloudTrail Enabled", "details": "At least one multi-region CloudTrail is enabled and logging."}
        else:
            # ADDED COMPLIANCE
            return {"status": "FAIL", "severity": "High", "check": "CloudTrail Enabled", "details": ["No multi-region CloudTrail is enabled and logging."], 
                    "fix": "Ensure a trail is set to 'Apply trail to all regions' and is 'Logging'.",
                    "compliance": {"CIS": "2.1.1", "ISO 27001": "A.12.4.1", "NIST CSF": "DE.CM-1"}}

    except ClientError as e:
        return {"status": "ERROR", "check": "CloudTrail Enabled", "details": f"Could not check CloudTrail: {e}"}

def check_rds_publicly_accessible():
    """Checks for public RDS instances in ALL regions. (CIS 6.1)"""
    findings = []
    regions = get_all_aws_regions()

    for region in regions:
        try:
            rds_client = boto3.client('rds', region_name=region)
            instances = rds_client.describe_db_instances()['DBInstances']

            for instance in instances:
                if instance.get('PubliclyAccessible', False):
                    findings.append(f"Region '{region}': RDS instance '{instance['DBInstanceIdentifier']}' is publicly accessible.")
        
        except ClientError as e:
            if e.response['Error']['Code'] in ['AuthFailure', 'UnauthorizedOperation', 'InvalidParameterValue']:
                continue
            else:
                findings.append(f"Region '{region}': Could not scan RDS. {e}")

    if not findings:
        return {"status": "PASS", "check": "RDS Public Access", "details": "No public RDS instances found in any region."}
    else:
        # ADDED COMPLIANCE
        return {"status": "FAIL", "severity": "Critical", "check": "RDS Public Access", "details": findings, 
                "fix": "Modify the RDS instance and set 'PubliclyAccessible' to 'No' under the 'Connectivity' settings.",
                "compliance": {"CIS": "6.1", "ISO 27001": "A.9.1.2", "NIST CSF": "PR.DS-2"}}

# --- HTML REPORT FUNCTION (MODIFIED FOR COMPLIANCE) ---
def generate_html_report(failed_findings, passed_count, total_checks):
    """Generates a simple HTML report from the scan results."""
    
    score = (passed_count / total_checks) * 100
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    html_style = """
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        h1 { color: #333; }
        h2 { color: #555; border-bottom: 2px solid #ccc; padding-bottom: 5px; }
        table { border-collapse: collapse; width: 100%; margin-top: 20px; }
        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        th { background-color: #f2f2f2; }
        .summary { background-color: #f9f9f9; padding: 20px; border-radius: 8px; }
        .score-pass { color: green; font-weight: bold; }
        .score-fail { color: red; font-weight: bold; }
        .details { font-family: 'Courier New', monospace; background: #eee; padding: 3px; }
        .fix { color: #006400; }
        
        /* Severity colors */
        .sev-critical { background-color: #ffcccc; font-weight: bold; color: #a00; }
        .sev-high { background-color: #ffe5cc; font-weight: bold; color: #a55; }
        .sev-medium { background-color: #fffacd; }
        
        /* Compliance text */
        .compliance { font-size: 0.9em; color: #555; }
    </style>
    """
    
    html_content = f"<html><head><title>AWS Compliance Report</title>{html_style}</head><body>"
    html_content += "<h1>AWS Security Compliance Report</h1>"
    
    score_color = "score-pass" if score > 80 else "score-fail"
    html_content += f"""
    <div class="summary">
        <h2>Scan Summary</h2>
        <p>Report Generated: {timestamp}</p>
        <p><b>Overall Score: <span class="{score_color}">{score:.0f}%</span></b></p>
        <p>({passed_count} / {total_checks} checks passed)</p>
    </div>
    """
    
    if failed_findings:
        html_content += "<h2> Failed Checks (Remediation Required)</h2>"
        # --- ADDED Compliance column ---
        html_content += "<table><tr><th>Severity</th><th>Check Name</th><th>Compliance Mappings</th><th>Finding Details</th><th>Remediation</th></tr>"
        
        for finding in failed_findings:
            details_str = "<br>".join([f"<span class='details'>{detail}</span>" for detail in finding['details']])
            
            severity = finding.get('severity', 'Medium')
            severity_class = f"sev-{severity.lower()}"
            
            # --- Format compliance data ---
            compliance = finding.get('compliance', {})
            compliance_str = ""
            if compliance:
                compliance_str = f"""
                    <span class="compliance"><b>CIS:</b> {compliance.get('CIS', 'N/A')}</span><br>
                    <span class="compliance"><b>ISO 27001:</b> {compliance.get('ISO 27001', 'N/A')}</span><br>
                    <span class="compliance"><b>NIST CSF:</b> {compliance.get('NIST CSF', 'N/A')}</span>
                """
            
            html_content += f"""
            <tr>
                <td class="{severity_class}">{severity}</td>
                <td>{finding['check']}</td>
                <td>{compliance_str}</td>
                <td>{details_str}</td>
                <td class='fix'>{finding['fix']}</td>
            </tr>
            """
        html_content += "</table>"
    else:
        html_content += "<h2> All checks passed!</h2>"

    html_content += "</body></html>"
    
    try:
        with open("report.html", "w", encoding="utf-8") as f:
            f.write(html_content)
        print(f"\n Successfully generated HTML report: report.html")
    except Exception as e:
        print(f"\n Error generating HTML report: {e}")

# --- MAIN SECTION (MODIFIED FOR COMPLIANCE) ---
if __name__ == "__main__":
    print("🚀 Starting Automated AWS Compliance Scan...")
    
    all_checks = [
        check_s3_public_access,
        check_iam_password_policy,
        check_ec2_security_groups,
        check_cloudtrail_enabled,
        check_rds_publicly_accessible
    ]
    
    passed_count = 0
    failed_findings = []

    print("   (Scanning all regions, this may take a moment...)")
    for check_func in all_checks:
        result = check_func()
        if result['status'] == "PASS":
            passed_count += 1
        elif result['status'] == "FAIL":
            failed_findings.append(result)
    
    severity_map = {"Critical": 1, "High": 2, "Medium": 3}
    failed_findings.sort(key=lambda x: severity_map.get(x.get('severity'), 4))
    
    total_checks = len(all_checks)
    score = (passed_count / total_checks) * 100
    
    print("\n" + "="*40)
    print("      AWS COMPLIANCE AUDIT REPORT")
    print("="*40)
    print(f"\n📊 FINAL SCORE: {score:.0f}% ({passed_count} / {total_checks} checks passed)")

    if failed_findings:
        print("\n FAILED CHECKS (Remediation Required):")
        for i, finding in enumerate(failed_findings, 1):
            severity = finding.get('severity', 'UNKNOWN')
            print(f"\n  {i}. SEVERITY: {severity}")
            print(f"     CHECK:    {finding['check']}")
            
            # --- ADDED compliance printout ---
            compliance = finding.get('compliance', {})
            if compliance:
                print(f"     MAPPING:  CIS: {compliance.get('CIS', 'N/A')}, ISO: {compliance.get('ISO 27001', 'N/A')}, NIST: {compliance.get('NIST CSF', 'N/A')}")
            
            details_str = "\n         - " + "\n         - ".join(finding['details'])
            print(f"     DETAILS: {details_str}")
            print(f"     FIX:     {finding['fix']}")
    else:
        print("\n All checks passed! Your AWS account is in good shape.")
        
    print("\n" + "="*40)
    
    generate_html_report(failed_findings, passed_count, total_checks)
    
    print("Scan complete.")