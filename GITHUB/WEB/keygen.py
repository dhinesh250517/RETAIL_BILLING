"""
keygen.py
---------
OWNER-ONLY tool. Keep this file (and its SECRET inside license_lock.py)
on your own computer only - NEVER copy it onto a customer's pendrive or
PC.

Usage:
    1. Customer sends you their Machine Code (shown on the activation
       screen when they open the app), e.g.:
           ABCD-1234-EFGH-5678
    2. Run this script:
           python keygen.py
    3. Pick key type:
         1) Permanent  - never expires (one-time sale)
         2) Subscription - expires after N months (renew every month/
            quarter/year - customer must re-enter a new key after that)
    4. Paste the Machine Code, enter months if subscription, and it
       prints the License Key - send that back to the customer to type
       into the activation screen.

You can also build this into its own tiny .exe for convenience
(pyinstaller --onefile keygen.py), and keep that exe only on your own
PC/phone-accessible drive, never on a customer machine.
"""

from license_lock import generate_license_key, generate_subscription_key, SECRET

if __name__ == "__main__":
    print("=== License Key Generator (owner-only, keep private) ===")
    print()
    print("Key type:")
    print("  1) Permanent      - never expires")
    print("  2) Subscription   - expires after N months, customer renews")
    choice = input("Choose (1/2): ").strip()

    code = input("Enter customer's Machine Code: ").strip()

    if choice == "2":
        months_text = input("How many months should this key last? [1]: ").strip() or "1"
        try:
            months = int(months_text)
        except ValueError:
            months = 1
        days = months * 30
        key = generate_subscription_key(code, days=days, secret=SECRET)
        print()
        print(f"SUBSCRIPTION License Key for {code} ({months} month(s), expires in {days} days):")
        print(f"    {key}")
        print()
        print("Send only this key to the customer. Remember to send them a")
        print("new key before/when this one expires, or the app will lock")
        print("them out and show the activation screen again.")
    else:
        key = generate_license_key(code, SECRET)
        print()
        print(f"PERMANENT License Key for {code}:")
        print(f"    {key}")
        print()
        print("Send only this key to the customer. It never expires.")
