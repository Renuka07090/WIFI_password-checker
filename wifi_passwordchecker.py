# -*- coding: utf-8 -*-
"""
Created on Sun May 24 18:54:13 2026

@author: Renuka
"""
#!/usr/bin/env python3
"""
WI-FI PASSWORD SECURITY AUDITOR - Cybersecurity Project
Audits saved Wi-Fi passwords on Windows and checks their strength.
Usage: python wifi_auditor.py
No admin rights needed!
"""

import subprocess
import re
import math
import platform
from datetime import datetime


# ─────────────────────────────────────────
#  COMMON WEAK PASSWORDS
# ─────────────────────────────────────────
COMMON_PASSWORDS = {
    "password", "12345678", "123456789", "password1",
    "iloveyou", "admin123", "letmein1", "welcome1",
    "monkey123", "dragon123", "qwerty123", "abc12345",
    "password123", "admin", "12341234", "11111111",
    "00000000", "99999999", "87654321", "pass1234"
}

KEYBOARD_PATTERNS = [
    "qwerty", "asdfgh", "zxcvbn", "12345678",
    "87654321", "qazwsx", "qwertyui"
]


def print_banner():
    print("=" * 60)
    print("    WI-FI PASSWORD SECURITY AUDITOR - Security Tool")
    print(f"    Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 60)


def get_wifi_profiles():
    """Get all saved Wi-Fi profile names on Windows."""
    try:
        result = subprocess.run(
            ["netsh", "wlan", "show", "profiles"],
            capture_output=True, text=True
        )
        profiles = re.findall(r"All User Profile\s*:\s*(.+)", result.stdout)
        return [p.strip() for p in profiles]
    except Exception as e:
        print(f"[ERROR] Could not get Wi-Fi profiles: {e}")
        return []


def get_wifi_password(profile):
    """Get password for a specific Wi-Fi profile."""
    try:
        result = subprocess.run(
            ["netsh", "wlan", "show", "profile",
             profile, "key=clear"],
            capture_output=True, text=True
        )
        # Get password
        password = re.findall(r"Key Content\s*:\s*(.+)", result.stdout)
        # Get security type
        security = re.findall(r"Authentication\s*:\s*(.+)", result.stdout)
        # Get encryption
        encryption = re.findall(r"Cipher\s*:\s*(.+)", result.stdout)

        return {
            "password": password[0].strip() if password else None,
            "security": security[0].strip() if security else "Unknown",
            "encryption": encryption[0].strip() if encryption else "Unknown"
        }
    except Exception as e:
        return {"password": None, "security": "Unknown", "encryption": "Unknown"}


def calculate_entropy(password):
    """Calculate password entropy in bits."""
    charset = 0
    if re.search(r'[a-z]', password): charset += 26
    if re.search(r'[A-Z]', password): charset += 26
    if re.search(r'[0-9]', password): charset += 10
    if re.search(r'[^a-zA-Z0-9]', password): charset += 32
    if charset == 0:
        return 0
    return round(len(password) * math.log2(charset), 2)


def analyze_password(password):
    """Analyze Wi-Fi password strength."""
    if not password:
        return None

    score = 0
    issues = []
    suggestions = []

    # Length check
    length = len(password)
    if length >= 16:
        score += 30
    elif length >= 12:
        score += 20
    elif length >= 8:
        score += 10
    else:
        issues.append(f"Too short ({length} chars, need 8+)")
        suggestions.append("Use at least 12 characters")

    # Character variety
    has_lower = bool(re.search(r'[a-z]', password))
    has_upper = bool(re.search(r'[A-Z]', password))
    has_digit = bool(re.search(r'[0-9]', password))
    has_symbol = bool(re.search(r'[^a-zA-Z0-9]', password))

    variety = sum([has_lower, has_upper, has_digit, has_symbol])
    score += variety * 10

    if not has_upper: suggestions.append("Add uppercase letters")
    if not has_digit: suggestions.append("Add numbers")
    if not has_symbol: suggestions.append("Add special characters")

    # Common password check
    if password.lower() in COMMON_PASSWORDS:
        issues.append("This is a very common password!")
        score -= 30

    # Keyboard pattern check
    pw_lower = password.lower()
    for pattern in KEYBOARD_PATTERNS:
        if pattern in pw_lower:
            issues.append(f"Contains keyboard pattern: {pattern}")
            suggestions.append("Avoid keyboard patterns like qwerty")
            score -= 15
            break

    # Repeated characters
    if re.search(r'(.)\1{2,}', password):
        issues.append("Contains repeated characters")
        suggestions.append("Avoid repeating same character 3+ times")
        score -= 10

    # All same character type
    if password.isdigit():
        issues.append("Only numbers — very weak!")
        suggestions.append("Mix letters, numbers and symbols")
        score -= 20

    if password.isalpha():
        issues.append("Only letters — weak!")
        suggestions.append("Add numbers and special characters")
        score -= 10

    # Entropy bonus
    entropy = calculate_entropy(password)
    if entropy >= 60: score += 20
    elif entropy >= 40: score += 10

    # Clamp score
    score = max(0, min(100, score))

    # Strength label
    if score >= 80:
        strength = "VERY STRONG 🟢"
    elif score >= 60:
        strength = "STRONG 🟡"
    elif score >= 40:
        strength = "MODERATE 🟠"
    elif score >= 20:
        strength = "WEAK 🔴"
    else:
        strength = "VERY WEAK ❌"

    return {
        "score": score,
        "strength": strength,
        "entropy": entropy,
        "length": length,
        "issues": issues,
        "suggestions": suggestions,
        "has_upper": has_upper,
        "has_lower": has_lower,
        "has_digit": has_digit,
        "has_symbol": has_symbol
    }


def security_rating(security_type):
    """Rate the Wi-Fi security protocol."""
    security_type = security_type.upper()
    if "WPA3" in security_type:
        return "🟢 Excellent (WPA3)"
    elif "WPA2" in security_type:
        return "🟡 Good (WPA2)"
    elif "WPA" in security_type:
        return "🟠 Outdated (WPA)"
    elif "WEP" in security_type:
        return "🔴 Dangerous (WEP - easily cracked!)"
    elif "OPEN" in security_type or "NONE" in security_type:
        return "❌ No Security (Open Network!)"
    else:
        return f"⚪ {security_type}"


def print_wifi_report(profile, info, analysis):
    print(f"\n{'─' * 60}")
    print(f"  📶 Network  : {profile}")
    print(f"  🔒 Security : {security_rating(info['security'])}")
    print(f"  🔐 Encryption: {info['encryption']}")

    if info['password']:
        pw = info['password']
        masked = pw[0] + '*' * (len(pw) - 2) + pw[-1] if len(pw) > 2 else '**'
        print(f"  🔑 Password : {masked} ({len(pw)} chars)")

        if analysis:
            print(f"  📊 Score    : {analysis['score']}/100")
            print(f"  💪 Strength : {analysis['strength']}")
            print(f"  📈 Entropy  : {analysis['entropy']} bits")

            print(f"\n  Character checks:")
            print(f"  {'✅' if analysis['has_upper'] else '❌'} Uppercase letters")
            print(f"  {'✅' if analysis['has_lower'] else '❌'} Lowercase letters")
            print(f"  {'✅' if analysis['has_digit'] else '❌'} Numbers")
            print(f"  {'✅' if analysis['has_symbol'] else '❌'} Special characters")

            if analysis['issues']:
                print(f"\n  ⚠️  Issues:")
                for issue in analysis['issues']:
                    print(f"    • {issue}")

            if analysis['suggestions']:
                print(f"\n  💡 Suggestions:")
                for s in analysis['suggestions']:
                    print(f"    • {s}")
    else:
        print(f"  🔑 Password : [Hidden or not saved]")


def print_summary(results):
    print(f"\n{'=' * 60}")
    print(f"  AUDIT SUMMARY")
    print(f"{'=' * 60}")
    print(f"  Total Networks Scanned : {len(results)}")

    if not results:
        return

    scored = [(r['profile'], r['analysis'])
              for r in results if r['analysis']]

    if scored:
        avg_score = sum(a['score'] for _, a in scored) / len(scored)
        print(f"  Average Password Score : {avg_score:.1f}/100")

        weak = [(p, a) for p, a in scored if a['score'] < 40]
        strong = [(p, a) for p, a in scored if a['score'] >= 60]

        print(f"  Strong Passwords       : {len(strong)}")
        print(f"  Weak Passwords         : {len(weak)}")

        if weak:
            print(f"\n  ⚠️  WEAK NETWORKS (change password!):")
            for profile, analysis in weak:
                print(f"    🔴 {profile} — Score: {analysis['score']}/100")

    # Save report
    filename = f"wifi_audit_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
    with open(filename, "w") as f:
        f.write("WI-FI SECURITY AUDIT REPORT\n")
        f.write(f"Date: {datetime.now()}\n")
        f.write(f"Networks Scanned: {len(results)}\n\n")
        for r in results:
            f.write(f"Network: {r['profile']}\n")
            f.write(f"Security: {r['info']['security']}\n")
            if r['analysis']:
                f.write(f"Score: {r['analysis']['score']}/100\n")
                f.write(f"Strength: {r['analysis']['strength']}\n")
            f.write("\n")
    print(f"\n  📄 Report saved: {filename}")


def main():
    print_banner()

    # Check Windows
    if platform.system() != "Windows":
        print("[ERROR] This tool works on Windows only.")
        print("  It uses 'netsh wlan' Windows commands.")
        return

    print("\n  Scanning saved Wi-Fi networks...")
    profiles = get_wifi_profiles()

    if not profiles:
        print("  No Wi-Fi profiles found.")
        return

    print(f"  Found {len(profiles)} saved network(s)!")

    results = []
    for profile in profiles:
        info = get_wifi_password(profile)
        analysis = None
        if info['password']:
            analysis = analyze_password(info['password'])
        print_wifi_report(profile, info, analysis)
        results.append({
            "profile": profile,
            "info": info,
            "analysis": analysis
        })

    print_summary(results)


if __name__ == "__main__":
    main()
