import streamlit as st
import pandas as pd
from main import run_scan, generate_html_report

# --- Page Configuration ---
st.set_page_config(
    page_title="AWS Compliance Scanner",
    page_icon="🛡️",
    layout="wide"
)

# --- Header ---
st.title("🛡️ Automated AWS Security Compliance Checker")
st.write("This tool scans your AWS account for common security misconfigurations and generates a compliance report.")


if st.button("Start Security Scan"):
    
    # 1. Run the scan
    with st.spinner("Scanning all AWS regions... (This may take a minute)"):
        passed_findings, failed_findings, total_checks = run_scan()
        
    st.success("Scan Complete!")
    
    # 2. Calculate score
    passed_count = len(passed_findings)
    score = (passed_count / total_checks) * 100
    
    # --- Display Summary Metrics ---
    st.header("📊 Compliance Summary")
    col1, col2, col3 = st.columns(3)
    col1.metric("Compliance Score", f"{score:.0f}%")
    col2.metric("Checks Passed", f"{passed_count} / {total_checks}")
    col3.metric("Failed Findings", f"{len(failed_findings)}")

    # --- Display Failed Findings ---
    if failed_findings:
        st.error(f"Found {len(failed_findings)} security risk(s):")
        
        display_data = []
        for f in failed_findings:
            display_data.append({
                "Severity": f.get('severity'),
                "Check": f.get('check'),
                "Details": ", ".join(f.get('details', [])),
                "Remediation": f.get('fix'),
                "CIS": f.get('compliance', {}).get('CIS', 'N/A'),
                "ISO 27001": f.get('compliance', {}).get('ISO 27001', 'N/A'),
                "NIST CSF": f.get('compliance', {}).get('NIST CSF', 'N/A')  # <-- THIS IS THE NEW LINE
            })
        
        st.dataframe(pd.DataFrame(display_data), width='stretch')
        
        # --- Add a download button for the HTML report ---
        generate_html_report(passed_findings, failed_findings, total_checks)
        with open("report.html", "r", encoding="utf-8") as f:
            html_data = f.read()
        
        st.download_button(
            label="Download Full HTML Report",
            data=html_data,
            file_name="aws_compliance_report.html",
            mime="text/html"
        )
        
    else:
        st.success("🎉 All checks passed! No security risks found.")

    # SHOW PASSED CHECKS ---
    if passed_findings:
        with st.expander(f"Show {len(passed_findings)} Passed Checks"):
            passed_data = []
            for f in passed_findings:
                passed_data.append({
                    "Check": f.get('check'),
                    "Details": f.get('details')
                })
            st.dataframe(pd.DataFrame(passed_data), width='stretch')