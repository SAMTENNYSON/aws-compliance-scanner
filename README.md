# Automated AWS Security Compliance Checker (ACS4)

This project is an automated, command-line tool for an Information Security Analysis and Audit course. It scans an Amazon Web Services (AWS) account for common security misconfigurations based on the services outlined in the project abstract.

The tool is written in Python and uses the `boto3` SDK to make live API calls to AWS.

## 🛡️ Checks Implemented

This tool audits 5 key AWS services and maps findings directly to CIS AWS Foundations Benchmarks:

1.  **S3 Public Access (CIS 1.2.1):** Checks if any S3 buckets are configured to allow public access.
2.  **IAM Password Policy (CIS 1.5-1.8):** Checks if the account's IAM password policy enforces strong standards (uppercase, lowercase, number, symbol).
3.  **EC2 Public SSH (CIS 5.1):** Scans all security groups for rules that allow unrestricted SSH (port 22) access from the internet (`0.0.0.0/0`).
4.  **CloudTrail Logging (CIS 2.1.1):** Verifies that at least one multi-region CloudTrail is enabled and actively logging.
5.  **RDS Public Access (CIS 6.1):** Checks if any RDS database instances are set to be publicly accessible.

## 🚀 How to Run

### Prerequisites
* Python 3.10+
* An AWS account
* An AWS IAM User with `ReadOnlyAccess` permissions

### 1. Setup Project
```bash
# Clone the repository (or download the files)
git clone [your-git-repo-url]
cd aws-compliance-scanner

# Create and activate a virtual environment
python3 -m venv venv
source venv/bin/activate