# app.py
# Advanced Email Validator with User‑Friendly UI (Single + Bulk)
# Features: enhanced syntax, IDNA, domain/MX, SMTP, catch‑all, disposable, role‑based, free/business,
# DNSBL best‑effort, deliverability score, charts, progress, and filtered downloads.

import streamlit as st
import pandas as pd
import re
import dns.resolver
import smtplib
import socket
import idna
import time
import random
import string
from functools import lru_cache
import altair as alt

# -------------------------------------
# App Config
# -------------------------------------
st.set_page_config(page_title="Email Validator", page_icon="📧", layout="wide")
APP_TITLE = "📧 Advanced Email Validation Tool"
APP_DESC = (
    "Validate single or bulk email addresses with syntax, DNS, MX, SMTP, disposable, role-based, "
    "catch-all, DNSBL checks, and a deliverability score. Export **All / Valid / Invalid** results."
)

# Some common disposable domains (extend as needed)
DISPOSABLE_DOMAINS = {
    "mailinator.com", "10minutemail.com", "guerrillamail.com", "tempmail.com",
    "yopmail.com", "trashmail.com", "getnada.com", "sharklasers.com",
    "dispostable.com", "temp-mail.org", "maildrop.cc", "moakt.com"
}

# Role-based local parts
ROLE_BASED_LOCALPARTS = {
    "admin", "administrator", "billing", "contact", "customerservice", "enquiries",
    "finance", "help", "hello", "info", "inquiry", "marketing", "newsletter",
    "no-reply", "noreply", "office", "postmaster", "privacy", "root", "sales",
    "security", "support", "team", "abuse", "webmaster", "jobs", "hr"
}

# Free email providers
FREE_PROVIDERS = {
    "gmail.com", "yahoo.com", "yahoo.co.in", "outlook.com", "hotmail.com",
    "live.com", "icloud.com", "aol.com", "proton.me", "protonmail.com", "zoho.com",
    "yandex.com", "gmx.com", "rediffmail.com", "mail.com"
}

# Public DNSBLs to check (best-effort; may not respond)
DNSBL_ZONES = [
    "bl.spamcop.net",
    "dnsbl.sorbs.net",
    "spam.dnsbl.sorbs.net"
]

# -------------------------------------
# Utilities
# -------------------------------------
def _rand_local_part(length=18):
    return "".join(random.choices(string.ascii_lowercase + string.digits, k=length))

def normalize(email: str):
    '''Trim whitespace, lower the domain, and split local/domain.
       Returns (original, local, domain, domain_idna)'''
    e = (email or "").strip()
    if "@" not in e:
        return e, "", "", ""
    local, domain = e.rsplit("@", 1)
    domain_lower = domain.strip().lower()
    # idna encode domain for DNS operations
    try:
        domain_idna = idna.encode(domain_lower).decode("ascii")
    except Exception:
        domain_idna = domain_lower  # fallback
    return e, local, domain_lower, domain_idna

# -------------------------------------
# Validation functions
# -------------------------------------
def is_valid_format_enhanced(email: str):
    '''
    RFC-like pragmatic validation:
    - total length <= 254, local <= 64
    - no consecutive dots, no leading/trailing dot in local
    - local allows common specials, domain labels 1-63 chars, TLD >= 2
    '''
    e, local, domain, _ = normalize(email)
    if not e or not local or not domain:
        return False, "Invalid Format: missing @ or parts"
    if len(e) > 254:
        return False, "Invalid Format: exceeds 254 chars"
    if len(local) > 64:
        return False, "Invalid Format: local-part exceeds 64 chars"
    if ".." in local or local.startswith(".") or local.endswith("."):
        return False, "Invalid Format: dots misused in local-part"
    # local-part regex with allowed specials
    local_regex = r"^(?!\.)[A-Za-z0-9!#$%&'*+/=?^_`{|}~\.-]+(?<!\.)$"
    if re.match(local_regex, local) is None:
        return False, "Invalid Format: illegal characters in local-part"
    # domain check (basic)
    domain_regex = r"^(?=.{1,253}$)([A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,}$"
    if re.match(domain_regex, domain) is None:
        return False, "Invalid Domain Format"
    return True, "OK"

@lru_cache(maxsize=10000)
def domain_exists(domain_idna: str):
    try:
        socket.gethostbyname(domain_idna)
        return True
    except socket.error:
        return False

@lru_cache(maxsize=10000)
def get_mx_records(domain_idna: str):
    try:
        answers = dns.resolver.resolve(domain_idna, "MX")
        # sort by preference (lowest first)
        recs = sorted([(r.preference, str(r.exchange).rstrip(".")) for r in answers], key=lambda x: x[0])
        return recs
    except Exception:
        return []

def has_mx_record(domain_idna: str):
    return len(get_mx_records(domain_idna)) > 0

def smtp_rcpt_status(email: str, timeout=8):
    '''Try to RCPT TO and return (ok:boolean, code:int, message:str).'''
    _, _, _, domain_idna = normalize(email)
    mx_records = get_mx_records(domain_idna)
    if not mx_records:
        return False, None, "No MX available"
    pref, host = mx_records[0]
    try:
        server = smtplib.SMTP(timeout=timeout)
        server.connect(host)
        server.helo(socket.gethostname())
        server.mail("validator@example.com")
        code, msg = server.rcpt(email)
        server.quit()
        return (code == 250), code, (msg.decode("utf-8", "ignore") if isinstance(msg, bytes) else str(msg))
    except Exception as e:
        return False, None, f"SMTP error: {e}"

def detect_catch_all(domain_idna: str, timeout=8):
    '''Sends RCPT to a random mailbox; if accepted => likely catch-all.'''
    mx_records = get_mx_records(domain_idna)
    if not mx_records:
        return False, "No MX available"
    test_email = f"{_rand_local_part()}@{domain_idna}"
    try:
        server = smtplib.SMTP(timeout=timeout)
        server.connect(mx_records[0][1])
        server.helo(socket.gethostname())
        server.mail("validator@example.com")
        code, _ = server.rcpt(test_email)
        server.quit()
        return (code == 250), f"SMTP RCPT code: {code}"
    except Exception as e:
        return False, f"SMTP error: {e}"

def dnsbl_check(hostname: str):
    '''Best-effort DNSBL check: resolve host -> IP, then query DNSBLs. Returns (listed:boolean, hits:list).'''
    try:
        ip = socket.gethostbyname(hostname)
    except Exception:
        return False, []
    parts = ip.split(".")
    if len(parts) != 4:
        return False, []
    reversed_ip = ".".join(reversed(parts))
    hits = []
    for zone in DNSBL_ZONES:
        query = f"{reversed_ip}.{zone}"
        try:
            dns.resolver.resolve(query, "A")
            hits.append(zone)
        except Exception:
            pass
    return (len(hits) > 0), hits

def classify_email_type(local: str, domain: str):
    is_role = local.lower() in ROLE_BASED_LOCALPARTS
    is_free = domain.lower() in FREE_PROVIDERS
    is_disposable = domain.lower() in DISPOSABLE_DOMAINS
    return is_role, is_free, is_disposable

def deliverability_score(flags: dict):
    '''Compute score 0..100 from checks.'''
    score = 0
    score += 20 if flags.get("format_ok") else 0
    score += 20 if flags.get("domain_exists") else 0
    score += 20 if flags.get("mx_present") else 0
    score += 20 if flags.get("smtp_ok") else 0
    # penalty buckets / bonuses
    if not flags.get("is_disposable"):
        score += 7
    if not flags.get("is_role"):
        score += 7
    if not flags.get("catch_all"):
        score += 6
    if flags.get("dnsbl_listed"):
        score -= 20
    return max(0, min(100, score))

def validate_email_full(email: str, depth="mx", enable_dnsbl=False, enable_catch_all=False):
    '''
    depth: 'format' | 'mx' | 'smtp'
    Returns dict with detailed fields.
    '''
    original, local, domain, domain_idna = normalize(email)

    # Format
    format_ok, format_reason = is_valid_format_enhanced(original)

    flags = {
        "format_ok": format_ok,
        "domain_exists": False,
        "mx_present": False,
        "smtp_ok": False,
        "is_role": False,
        "is_free": False,
        "is_disposable": False,
        "catch_all": False,
        "dnsbl_listed": False
    }

    reason = None
    smtp_code = None
    smtp_msg = None
    mx_host = None
    dnsbl_hits = []

    if not format_ok:
        reason = format_reason
    else:
        # classify
        is_role, is_free, is_disposable = classify_email_type(local, domain)
        flags.update({"is_role": is_role, "is_free": is_free, "is_disposable": is_disposable})

        if depth in ("mx", "smtp"):
            flags["domain_exists"] = domain_exists(domain_idna)
            if not flags["domain_exists"]:
                reason = "Domain not found"
            else:
                mx_records = get_mx_records(domain_idna)
                flags["mx_present"] = len(mx_records) > 0
                if not flags["mx_present"]:
                    reason = "No MX record"
                else:
                    mx_host = mx_records[0][1]

                    # Optional DNSBL
                    if enable_dnsbl and mx_host:
                        listed, hits = dnsbl_check(mx_host)
                        flags["dnsbl_listed"] = listed
                        dnsbl_hits = hits

                    # Optional catch-all detection
                    if enable_catch_all:
                        ca, _ = detect_catch_all(domain_idna)
                        flags["catch_all"] = ca

                    # SMTP verify
                    if depth == "smtp":
                        ok, code, msg = smtp_rcpt_status(original)
                        flags["smtp_ok"] = ok
                        smtp_code, smtp_msg = code, msg
                        if not ok:
                            if code == 550:
                                reason = "Mailbox unavailable (550)"
                            elif code == 552:
                                reason = "Mailbox full (552)"
                            elif code in (450, 451, 452):
                                reason = f"Temporary failure ({code})"
                            else:
                                reason = f"SMTP check failed ({code})" if code else (msg or "SMTP check failed")

    status_valid = (
        flags["format_ok"] and
        (depth == "format" or (flags["domain_exists"] and flags["mx_present"] and (depth != "smtp" or flags["smtp_ok"])))
    )
    status = "Valid" if status_valid else "Invalid"
    score = deliverability_score(flags)

    return {
        "email": original,
        "status": ("✅ " if status == "Valid" else "❌ ") + status,
        "reason": reason or "OK",
        "type": ("Free" if flags["is_free"] else "Business"),
        "disposable": "Yes" if flags["is_disposable"] else "No",
        "role_based": "Yes" if flags["is_role"] else "No",
        "catch_all": "Yes" if flags["catch_all"] else "No",
        "dnsbl_listed": "Yes" if flags["dnsbl_listed"] else "No",
        "mx_host": mx_host or "",
        "smtp_code": smtp_code if smtp_code is not None else "",
        "smtp_msg": smtp_msg or "",
        "score": score
    }

# -------------------------------------
# UI Helper Components
# -------------------------------------
def status_badge(text: str):
    color = "#22c55e" if "Valid" in text else "#ef4444"
    return f"""
    <span style='
        display:inline-block;
        background:{color};
        padding:4px 10px;
        border-radius:12px;
        color:white;
        font-weight:600;
        font-size:12px;
        white-space:nowrap;
    '>{text}</span>
    """


def info_kv(label: str, value: str):
    return f'''
    <div style='display:flex;justify-content:space-between;padding:10px 14px;border-bottom:1px solid #eee;'>
        <span style='color:#6b7280'>{label}</span>
        <span style='font-weight:600'>{value}</span>
    </div>
    '''

def single_result_card(res: dict):
    st.subheader("Result")
    st.markdown(status_badge(f"{res['email']} → {res['status']}"), unsafe_allow_html=True)
    st.markdown(
    f"""
    <div style="display:inline-block; padding:6px 12px; border-radius:8px; 
                background-color:#f1f1f1; font-size:14px; font-weight:500; 
                color:#333; margin-top:8px;">
        {res['email']} → {res['status']}
    </div>
    """,
    unsafe_allow_html=True
)

    # st.markdown(f"<p style='font-size:14px; color:green;'>{status}</p>", unsafe_allow_html=True)
    st.progress(int(res.get("score", 0)) / 100.0)
    c1, c2, c3 = st.columns(3)
    c1.metric("Reason", res.get("reason", "OK"))
    c2.metric("Type", res.get("type", "—"))
    c3.metric("Score", res.get("score", 0))

    with st.expander("Details"):
        html = "".join([
            info_kv("Disposable", res.get("disposable", "No")),
            info_kv("Role-based", res.get("role_based", "No")),
            info_kv("Catch-all", res.get("catch_all", "No")),
            info_kv("DNSBL Listed", res.get("dnsbl_listed", "No")),
            info_kv("MX Host", res.get("mx_host", "—")),
            info_kv("SMTP Code", str(res.get("smtp_code", "—"))),
            info_kv("SMTP Message", res.get("smtp_msg", "—")),
        ])
        st.markdown(f"<div style='border:1px solid #eee;border-radius:12px'>{html}</div>", unsafe_allow_html=True)

def pie_chart(valid: int, invalid: int):
    data = pd.DataFrame({
        "Status": ["Valid", "Invalid"],
        "Count": [valid, invalid]
    })
    chart = alt.Chart(data).mark_arc(outerRadius=120).encode(
        theta=alt.Theta(field="Count", type="quantitative"),
        color=alt.Color(field="Status", type="nominal"),
        tooltip=["Status", "Count"]
    ).properties(width=300, height=300)
    return chart

def bar_chart(valid: int, invalid: int):
    data = pd.DataFrame({
        "Status": ["Valid", "Invalid"],
        "Count": [valid, invalid]
    })
    chart = alt.Chart(data).mark_bar().encode(
        x=alt.X("Status:N", sort=["Valid", "Invalid"]),
        y="Count:Q",
        color="Status:N",
        tooltip=["Status", "Count"]
    ).properties(height=300)
    return chart

# -------------------------------------
# Sidebar Controls
# -------------------------------------
st.title(APP_TITLE)
st.write(APP_DESC)

mode = st.sidebar.radio("Choose Validation Type:", ["Single Email", "Bulk CSV Upload"])

validation_mode = st.sidebar.radio(
    "Validation Depth:",
    ["Format Only", "Format + Domain/MX", "Full (with SMTP)"]
)
mode_map = {"Format Only": "format", "Format + Domain/MX": "mx", "Full (with SMTP)": "smtp"}
selected_mode = mode_map[validation_mode]

st.sidebar.markdown("**Advanced Options**")
enable_catch_all = st.sidebar.checkbox("Detect Catch‑all Domains (SMTP)", value=False)
enable_dnsbl = st.sidebar.checkbox("Check DNSBL Listings (best‑effort)", value=False)
st.sidebar.info("Note: SMTP, catch‑all, and DNSBL checks can be slow for very large lists.")

# -------------------------------------
# Single Email
# -------------------------------------
if mode == "Single Email":
    email_input = st.text_input("Enter an email to validate:")
    if st.button("Check Email", use_container_width=False):
        if email_input.strip():
            with st.spinner("Validating..."):
                res = validate_email_full(email_input.strip(), selected_mode, enable_dnsbl, enable_catch_all)
            single_result_card(res)
        else:
            st.warning("⚠️ Please enter an email address.")

# -------------------------------------
# Bulk CSV
# -------------------------------------
else:
    uploaded_file = st.file_uploader("Upload CSV file (first column should contain emails)", type=["csv"])
    if uploaded_file is not None:
        df = pd.read_csv(uploaded_file)
        email_col = df.columns[0]
        st.write(f"Detected email column: **{email_col}**")

        run = st.button("Validate Emails", use_container_width=False)
        if run:
            progress_bar = st.progress(0)
            status_text = st.empty()

            results = []
            total = len(df)

            for i, email in enumerate(df[email_col].astype(str), 1):
                res = validate_email_full(email, selected_mode, enable_dnsbl, enable_catch_all)
                results.append(res)
                progress_bar.progress(int(i / max(1, total) * 100))
                status_text.text(f"Processing {i}/{total} emails...")
                # tiny sleep to keep UI responsive
                time.sleep(0.001)

            out = pd.DataFrame(results)

            # Summary stats
            total_n = len(out)
            valid_n = (out["status"].str.contains("✅")).sum()
            invalid_n = total_n - valid_n
            valid_pct = (valid_n / total_n * 100) if total_n > 0 else 0.0

            st.success("Validation complete!")
            m1, m2, m3 = st.columns(3)
            m1.metric("Total Emails", total_n)
            m2.metric("✅ Valid", f"{valid_n} ({valid_pct:.2f}%)")
            m3.metric("❌ Invalid", invalid_n)

            # Charts
            c1, c2 = st.columns([1,1])
            with c1:
                st.altair_chart(pie_chart(valid_n, invalid_n), use_container_width=True)
            with c2:
                st.altair_chart(bar_chart(valid_n, invalid_n), use_container_width=True)

            st.subheader("Preview (first 200 rows)")
            st.dataframe(out.head(200))

            # Export options
            st.subheader("Export Results")
            export_option = st.radio(
                "Choose export type:",
                ["All Results", "Only Valid", "Only Invalid"],
                horizontal=True
            )

            if export_option == "Only Valid":
                export_df = out[out["status"].str.contains("✅")]
            elif export_option == "Only Invalid":
                export_df = out[~out["status"].str.contains("✅")]
            else:
                export_df = out

            csv = export_df.to_csv(index=False).encode("utf-8")
            st.download_button(
                "📥 Download CSV",
                data=csv,
                file_name="email_validation_results.csv",
                mime="text/csv",
                use_container_width=True
            )

            st.caption("Columns: email, status, reason, type, disposable, role_based, catch_all, dnsbl_listed, mx_host, smtp_code, smtp_msg, score")
