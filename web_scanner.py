import tkinter as tk
from tkinter import messagebox, filedialog
import requests
from urllib.parse import urlparse
from datetime import datetime

# Security headers
SECURITY_HEADERS = {
    "Content-Security-Policy": "Helps protect against XSS",
    "Strict-Transport-Security": "Enforces HTTPS",
    "X-Content-Type-Options": "Prevents MIME sniffing",
    "X-Frame-Options": "Helps prevent clickjacking",
    "Referrer-Policy": "Controls referrer information",
    "Permissions-Policy": "Restricts browser features"
}

report_text = ""

# Colors
BG = "#0f172a"
CARD = "#1e293b"
BLUE = "#38bdf8"
GREEN = "#22c55e"
WHITE = "#ffffff"


def scan_website():
    global report_text

    report_text = ""
    url = url_entry.get().strip()

    if not url:
        messagebox.showwarning(
            "Warning", "Please enter a website URL!"
        )
        return

    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    parsed = urlparse(url)

    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        messagebox.showerror(
            "Error", "Please enter a valid URL."
        )
        return

    result_box.delete("1.0", tk.END)
    result_box.insert(tk.END, "Scanning website...\n")
    status_label.config(text="Scanning...", fg="yellow")
    root.update_idletasks()

    try:
        response = requests.get(
            url,
            timeout=10,
            allow_redirects=True
        )

        headers = response.headers
        final_url = response.url

        report = []
        score = 0
        total = len(SECURITY_HEADERS) + 1

        report.append("=" * 55)
        report.append("AUTOMATED WEB SECURITY SCANNER")
        report.append("=" * 55)
        report.append(f"Website: {url}")
        report.append(f"Final URL: {final_url}")
        report.append(
            f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
        )
        report.append(f"HTTP Status: {response.status_code}")

        # HTTPS Check
        report.append("\n--- HTTPS SECURITY ---")

        is_https = urlparse(final_url).scheme == "https"

        if is_https:
            report.append("[PASS] HTTPS is enabled")
            score += 1
        else:
            report.append("[WARNING] HTTPS is not enabled")

        # Security Headers
        report.append("\n--- SECURITY HEADERS ---")

        for header, description in SECURITY_HEADERS.items():

            if header == "Strict-Transport-Security" and not is_https:
                report.append(
                    "[INFO] Strict-Transport-Security "
                    "is applicable to HTTPS responses."
                )
                continue

            if header in headers:
                report.append(f"[PASS] {header} is present")
                score += 1
            else:
                report.append(f"[WARNING] Missing {header}")
                report.append(f"Purpose: {description}")

        # CORS Check
        report.append("\n--- CORS SECURITY ---")

        cors = headers.get("Access-Control-Allow-Origin")

        if cors == "*":
            report.append(
                "[INFO] Wildcard CORS origin detected."
            )
            report.append(
                "Review whether public cross-origin access is intended."
            )
        elif cors:
            report.append(f"[INFO] Allowed Origin: {cors}")
        else:
            report.append(
                "[INFO] No Access-Control-Allow-Origin "
                "header found."
            )

        credentials = headers.get(
            "Access-Control-Allow-Credentials", ""
        )

        if credentials.lower() == "true":
            report.append(
                "[INFO] Cross-origin credentials are enabled."
            )

        # Cookie Check
        report.append("\n--- COOKIE SECURITY ---")

        raw_headers = response.raw.headers
        cookies = (
            raw_headers.getlist("Set-Cookie")
            if hasattr(raw_headers, "getlist")
            else []
        )

        if not cookies:
            report.append(
                "[INFO] No cookies were set in this response."
            )

        for cookie in cookies:
            cookie_name = cookie.split("=", 1)[0]
            attributes = {
                part.strip().split("=", 1)[0].lower()
                for part in cookie.split(";")[1:]
            }

            report.append(f"\nCookie: {cookie_name}")

            for attribute in ("secure", "httponly", "samesite"):
                if attribute in attributes:
                    report.append(
                        f"[PASS] {attribute} attribute present"
                    )
                else:
                    report.append(
                        f"[WARNING] {attribute} attribute missing"
                    )

        # Security Score
        report.append("\n--- SECURITY SCORE ---")

        percentage = round((score / total) * 100, 2)

        if percentage >= 80:
            risk = "LOW CONFIGURATION RISK"
        elif percentage >= 50:
            risk = "MEDIUM CONFIGURATION RISK"
        else:
            risk = "HIGH CONFIGURATION RISK"

        report.append(
            f"Security Configuration Score: {percentage}%"
        )
        report.append(f"Assessment: {risk}")

        report.append(
            "\nNote: This is a basic configuration check, "
            "not a complete vulnerability assessment."
        )

        report_text = "\n".join(report)

        result_box.delete("1.0", tk.END)
        result_box.insert(tk.END, report_text)

        score_label.config(
            text=f"Security Score: {percentage}%"
        )

        risk_label.config(text=risk)

        status_label.config(
            text="Scan Completed Successfully!",
            fg=GREEN
        )

    except requests.exceptions.RequestException as e:
        result_box.delete("1.0", tk.END)
        result_box.insert(
            tk.END, f"Unable to scan website:\n{e}"
        )
        status_label.config(
            text="Scan Failed", fg="#ef4444"
        )


def save_report():
    if not report_text:
        messagebox.showwarning(
            "Warning", "Please scan a website first!"
        )
        return

    filename = filedialog.asksaveasfilename(
        title="Save Security Report",
        defaultextension=".txt",
        initialfile="Security_Scan_Report.txt",
        filetypes=[("Text Files", "*.txt")]
    )

    if filename:
        try:
            with open(filename, "w", encoding="utf-8") as file:
                file.write(report_text)

            messagebox.showinfo(
                "Success", "Report downloaded successfully!"
            )
        except OSError as e:
            messagebox.showerror(
                "Save Error", str(e)
            )


# Main Window
root = tk.Tk()
root.title("Automated Web Security Scanner")
root.geometry("1000x700")
root.minsize(750, 500)
root.configure(bg=BG)

# Title
title = tk.Label(
    root,
    text="🛡 AUTOMATED WEB SECURITY SCANNER",
    font=("Arial", 22, "bold"),
    bg=BG,
    fg=BLUE
)
title.pack(pady=(15, 5))

subtitle = tk.Label(
    root,
    text="Cybersecurity Project | Website Security Analysis",
    font=("Arial", 11),
    bg=BG,
    fg=WHITE
)
subtitle.pack(pady=5)

# URL Section
url_label = tk.Label(
    root,
    text="Enter Website URL:",
    font=("Arial", 12, "bold"),
    bg=BG,
    fg=WHITE
)
url_label.pack(pady=(10, 5))

url_entry = tk.Entry(
    root,
    width=65,
    font=("Arial", 12),
    bg=CARD,
    fg=WHITE,
    insertbackground=WHITE
)
url_entry.pack(pady=5)
url_entry.insert(0, "https://example.com")

# Buttons at the top
button_frame = tk.Frame(root, bg=BG)
button_frame.pack(pady=12)

scan_button = tk.Button(
    button_frame,
    text="SCAN WEBSITE",
    command=scan_website,
    font=("Arial", 12, "bold"),
    bg="#0284c7",
    fg=WHITE,
    width=20,
    height=2,
    cursor="hand2"
)
scan_button.pack(side="left", padx=10)

download_button = tk.Button(
    button_frame,
    text="DOWNLOAD REPORT",
    command=save_report,
    font=("Arial", 12, "bold"),
    bg="#16a34a",
    fg=WHITE,
    width=22,
    height=2,
    cursor="hand2"
)
download_button.pack(side="left", padx=10)

# Score Section
score_frame = tk.Frame(root, bg=BG)
score_frame.pack(pady=8)

score_label = tk.Label(
    score_frame,
    text="Security Score: --",
    font=("Arial", 14, "bold"),
    bg=BG,
    fg=BLUE
)
score_label.pack(side="left", padx=20)

risk_label = tk.Label(
    score_frame,
    text="Risk: Not Scanned",
    font=("Arial", 12, "bold"),
    bg=BG,
    fg=GREEN
)
risk_label.pack(side="left", padx=20)

# Results Heading
result_label = tk.Label(
    root,
    text="Security Scan Results",
    font=("Arial", 15, "bold"),
    bg=BG,
    fg=BLUE
)
result_label.pack(pady=5)

# Results Box
result_frame = tk.Frame(root, bg=CARD)
result_frame.pack(
    padx=20,
    pady=5,
    fill="both",
    expand=True
)

scrollbar = tk.Scrollbar(result_frame)
scrollbar.pack(side="right", fill="y")

result_box = tk.Text(
    result_frame,
    font=("Consolas", 11),
    bg=CARD,
    fg="#00ff99",
    insertbackground=WHITE,
    yscrollcommand=scrollbar.set,
    wrap="word"
)
result_box.pack(
    side="left",
    fill="both",
    expand=True
)

scrollbar.config(command=result_box.yview)

# Status
status_label = tk.Label(
    root,
    text="Ready to Scan",
    font=("Arial", 11),
    bg=BG,
    fg="yellow"
)
status_label.pack(pady=10)

root.mainloop()