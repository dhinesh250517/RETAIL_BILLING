"""
license_lock.py
----------------
Simple offline, machine-locked license system.

WHY THIS EXISTS
---------------
The exe + shop_data.db normally sit together in one portable folder.
Anyone who copies that whole folder to a pendrive can hand it to a
different shop and it will run there too - there is nothing in a plain
.exe/.db pair that ties it to one computer.

This module fixes that: on first launch the app reads a fingerprint
from the current PC's hardware, and refuses to run any further unless
it has been "activated" for THAT exact fingerprint. Copying the folder
to a different PC produces a different fingerprint, so the old
activation simply stops working there and the app shows an activation
screen instead of opening.

HOW TO ACTIVATE A NEW CUSTOMER PC
----------------------------------
1. Run the app on the customer's PC. It shows a "Machine Code" (e.g.
   ABCD-1234-EFGH-5678) and asks for a License Key.
2. Send that Machine Code to yourself (owner) - WhatsApp/call, NOT via
   the pendrive.
3. Run keygen.py (kept only on YOUR computer, never given to
   customers) with that Machine Code to produce the matching License
   Key.
4. Give that License Key to the customer to type into the activation
   screen. It is saved locally and the app unlocks permanently on that
   PC only.

NOTE ON SECURITY
-----------------
This stops an ordinary customer from copying the folder and reselling
it - which is the realistic threat here. It is not unbreakable against
someone willing to reverse-engineer the .exe; no purely offline scheme
is. Combine with keeping keygen.py/SECRET private and, if you ever want
stronger protection, move the secret/verification to a small online
server instead of embedding it in the app.
"""

import hashlib
import hmac
import os
import subprocess
import sys
import platform
import uuid
from datetime import date, datetime, timedelta

# ---------------------------------------------------------------------
# IMPORTANT: change this to your own random secret before shipping, and
# never share this file (or keygen.py) with customers. Keep one copy
# safe on your own PC only. Anyone with this secret can generate valid
# keys for any machine.
# ---------------------------------------------------------------------
SECRET = b"CHANGE-THIS-TO-YOUR-OWN-RANDOM-SECRET-STRING-2026"

APP_NAME = "SriBillingApp"  # used to name the hidden license folder

# Shown to shopkeepers in the low-days-left warning popup and in the
# Settings screen's license section - change to your own number.
SUPPORT_CONTACT = "9150231058"

# How many days before a subscription expires the app starts warning
# the shopkeeper on every launch, so they have time to arrange renewal
# before actually getting locked out.
WARN_DAYS_BEFORE_EXPIRY = 2


def _license_dir():
    """
    Folder where the activation file is stored. Deliberately OUTSIDE the
    exe's own folder (in the user's local app-data area) so copying the
    exe+db folder to a pendrive/another PC does NOT carry the license
    file along with it.
    """
    if platform.system() == "Windows":
        base = os.environ.get("LOCALAPPDATA") or os.path.expanduser("~")
    else:
        base = os.path.expanduser("~/.local/share")
    path = os.path.join(base, APP_NAME)
    os.makedirs(path, exist_ok=True)
    return path


def _license_file():
    return os.path.join(_license_dir(), "license.dat")


def _windows_machine_guid():
    """Best-effort stable Windows machine identifier."""
    try:
        # Hide the console window that a spawned "reg.exe" would otherwise
        # briefly flash open in a windowed/onefile build - on some
        # machines that console-subsystem spin-up (plus AV/Defender
        # inspecting the new process) is what makes this call feel slow.
        # A short timeout also stops one dodgy machine from ever hanging
        # the app for a long time on this.
        startupinfo = None
        creationflags = 0
        if platform.system() == "Windows":
            startupinfo = subprocess.STARTUPINFO()
            startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
            creationflags = subprocess.CREATE_NO_WINDOW

        out = subprocess.check_output(
            ["reg", "query",
             r"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Cryptography",
             "/v", "MachineGuid"],
            stderr=subprocess.DEVNULL, text=True,
            startupinfo=startupinfo, creationflags=creationflags,
            timeout=5,
        )
        for line in out.splitlines():
            if "MachineGuid" in line:
                return line.strip().split()[-1]
    except Exception:
        pass
    return ""


# Cache: the fingerprint never changes during a run (the underlying MAC
# address / machine GUID don't change while the app is open), but every
# call used to re-spawn a "reg query" subprocess to recompute it. That
# subprocess is the slow part, and it was being paid for again on every
# single screen that checks license status - app startup (twice: once
# in is_activated(), once in the expiry-warning check), opening
# Settings, and opening the Admin Panel (twice there alone). Computing
# it once and reusing the result is what actually fixes the "password
# area / Settings / Admin Panel opens slowly" complaint - everything
# else in the app never touches this code path, which is why only
# these screens were slow.
_fingerprint_cache = None


def get_machine_fingerprint():
    """
    Build a fingerprint from things that stay the same on one PC but
    differ across PCs: network MAC + (on Windows) the machine GUID.
    Returned as a short human-typeable code, e.g. ABCD-1234-EFGH-5678.
    Computed once per app run and cached - see note above.
    """
    global _fingerprint_cache
    if _fingerprint_cache is not None:
        return _fingerprint_cache

    parts = [str(uuid.getnode())]
    guid = _windows_machine_guid()
    if guid:
        parts.append(guid)
    else:
        parts.append(platform.node())

    raw = "|".join(parts).encode("utf-8")
    digest = hashlib.sha256(raw).hexdigest().upper()[:16]
    _fingerprint_cache = "-".join(digest[i:i + 4] for i in range(0, 16, 4))
    return _fingerprint_cache


def generate_license_key(machine_code, secret=SECRET):
    """
    Derives the PERMANENT license key that matches a given machine code.
    Never expires. Used by keygen.py (owner-only tool) - kept here too so
    both files stay in sync, but keygen.py is what you actually run.
    """
    clean = machine_code.replace("-", "").upper().encode("utf-8")
    sig = hmac.new(secret, clean, hashlib.sha256).hexdigest().upper()[:16]
    return "-".join(sig[i:i + 4] for i in range(0, 16, 4))


def generate_subscription_key(machine_code, days=30, secret=SECRET, from_date=None):
    """
    Derives a SUBSCRIPTION license key that matches a given machine code
    AND expires `days` from today (default 30, i.e. one month).

    The expiry date is embedded right inside the key itself (last 8
    digits, YYYYMMDD) so the customer only ever has to type ONE key - no
    separate "enter your expiry date" field needed. The date is covered
    by the same HMAC signature as the machine code, so nobody can edit
    the visible date part to extend it themselves; changing even one
    digit makes the signature check fail.

    Format: SIGN-SIGN-SIGN-SIGN-YYYYMMDD, e.g. A1B2-C3D4-E5F6-0718-20260813
    """
    expiry = (from_date or date.today()) + timedelta(days=days)
    expiry_str = expiry.strftime("%Y%m%d")
    clean = machine_code.replace("-", "").upper()
    raw = f"{clean}|{expiry_str}|SUB".encode("utf-8")
    sig = hmac.new(secret, raw, hashlib.sha256).hexdigest().upper()[:16]
    sig_fmt = "-".join(sig[i:i + 4] for i in range(0, 16, 4))
    return f"{sig_fmt}-{expiry_str}"


def _validate_key(key, machine_code=None, secret=SECRET):
    """
    Checks a key against a machine code and figures out which of the two
    key TYPES it is, purely from its shape:
      - 16 hex chars total            -> PERMANENT key (old style, never expires)
      - 16 hex chars + 8 digit date   -> SUBSCRIPTION key (expires on that date)

    Returns (is_valid, kind, expiry_date_or_None).
    `is_valid` only reflects whether the signature matches this machine -
    it does NOT check whether a subscription key's date has already
    passed; callers (is_activated / try_activate) decide what to do with
    an expired-but-genuine key.
    """
    machine_code = machine_code or get_machine_fingerprint()
    clean_machine = machine_code.replace("-", "").upper()
    clean_key = "".join(ch for ch in key.strip().upper() if ch.isalnum())

    if len(clean_key) == 16:
        expected = hmac.new(secret, clean_machine.encode("utf-8"), hashlib.sha256).hexdigest().upper()[:16]
        if hmac.compare_digest(clean_key, expected):
            return True, "permanent", None
        return False, None, None

    if len(clean_key) == 24 and clean_key[16:].isdigit():
        sig_part, expiry_str = clean_key[:16], clean_key[16:]
        raw = f"{clean_machine}|{expiry_str}|SUB".encode("utf-8")
        expected = hmac.new(secret, raw, hashlib.sha256).hexdigest().upper()[:16]
        if hmac.compare_digest(sig_part, expected):
            try:
                expiry_date = datetime.strptime(expiry_str, "%Y%m%d").date()
            except ValueError:
                return False, None, None
            return True, "subscription", expiry_date
        return False, None, None

    return False, None, None


def _is_key_valid_for_this_machine(key):
    valid, kind, expiry = _validate_key(key)
    if not valid:
        return False
    if kind == "subscription" and date.today() > expiry:
        return False  # genuine key, but the month is up
    return True


def is_activated():
    try:
        with open(_license_file(), "r", encoding="utf-8") as f:
            saved_key = f.read().strip()
    except FileNotFoundError:
        return False
    return _is_key_valid_for_this_machine(saved_key)


def get_saved_license_status():
    """
    Looks at whatever key is currently saved on this PC (even if it's a
    genuine-but-expired subscription key) and describes it, so the
    activation screen can show something more useful than a generic
    "not activated" - e.g. "Your subscription expired on 13-08-2026".
    Returns None if there's no saved key or it doesn't belong to this
    machine at all (e.g. copied-in from another PC / tampered).
    """
    try:
        with open(_license_file(), "r", encoding="utf-8") as f:
            saved_key = f.read().strip()
    except FileNotFoundError:
        return None
    valid, kind, expiry = _validate_key(saved_key)
    if not valid:
        return None
    days_left = (expiry - date.today()).days if kind == "subscription" else None
    return {
        "kind": kind,
        "expiry": expiry,
        "expired": bool(kind == "subscription" and date.today() > expiry),
        "days_left": days_left,
        "should_warn": bool(
            kind == "subscription" and days_left is not None
            and 0 <= days_left <= WARN_DAYS_BEFORE_EXPIRY
        ),
    }


def save_activation(key):
    with open(_license_file(), "w", encoding="utf-8") as f:
        f.write(key.strip().upper())


def try_activate(key):
    if _is_key_valid_for_this_machine(key):
        save_activation(key)
        return True
    return False


def revoke_activation():
    """
    OWNER-ONLY action (called from the secret Admin Panel, behind the
    admin password). Deletes the saved license on this PC so the app
    goes back to the activation screen the next time it starts - e.g.
    for a customer who stopped paying, or to force an immediate manual
    lock. Safe to call even if nothing is currently saved.
    """
    try:
        os.remove(_license_file())
        return True
    except FileNotFoundError:
        return False


# --- optional standalone Tkinter activation screen -------------------
def show_activation_window(on_success):
    """
    Shows a simple activation dialog. Calls on_success() once the
    machine is activated. Exits the process if the user closes the
    window without activating.
    """
    import tkinter as tk
    from tkinter import messagebox

    win = tk.Tk()
    win.title("Activate Software")
    win.geometry("440x280")
    win.resizable(False, False)

    status = get_saved_license_status()
    if status and status["expired"]:
        header_text = "Your subscription has expired"
        sub_text = f"It expired on {status['expiry'].strftime('%d-%m-%Y')}. Enter a new License Key to continue."
    else:
        header_text = "This PC is not activated yet"
        sub_text = "Send this Machine Code to your software provider:"

    tk.Label(win, text=header_text,
             font=("Segoe UI", 12, "bold"), fg=("#b91c1c" if (status and status["expired"]) else "#111827")
             ).pack(pady=(16, 4))

    code = get_machine_fingerprint()
    tk.Label(win, text=sub_text,
             font=("Segoe UI", 9), wraplength=380, justify="center").pack(pady=(6, 2))

    code_var = tk.StringVar(value=code)
    entry_code = tk.Entry(win, textvariable=code_var, font=("Consolas", 13),
                           justify="center", state="readonly", width=22)
    entry_code.pack(pady=4)

    tk.Label(win, text="Enter the License Key you received:",
             font=("Segoe UI", 9)).pack(pady=(14, 2))
    key_var = tk.StringVar()
    entry_key = tk.Entry(win, textvariable=key_var, font=("Consolas", 13),
                          justify="center", width=22)
    entry_key.pack(pady=4)

    def do_activate():
        if try_activate(key_var.get()):
            messagebox.showinfo("Activated", "This PC is now activated.")
            win.destroy()
            on_success()
        else:
            messagebox.showerror("Invalid Key",
                                  "This key does not match this PC.\n"
                                  "Double-check the Machine Code you sent.")

    tk.Button(win, text="Activate", font=("Segoe UI", 10, "bold"),
              bg="#2563eb", fg="white", command=do_activate).pack(pady=16)

    def on_close():
        win.destroy()
        sys.exit(0)

    win.protocol("WM_DELETE_WINDOW", on_close)
    win.mainloop()
