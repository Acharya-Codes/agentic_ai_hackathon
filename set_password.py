"""Create (or replace) your GuberoAI login. Run it yourself in a terminal:

    python set_password.py

Your password is typed hidden and is never saved: only a salted hash goes into
auth.json. Never paste your password into a chat or a message.
"""
import getpass
import os

import auth


def main():
    if os.path.exists(auth.AUTH_FILE):
        if input("An account already exists. Replace it? Type yes to continue: ").strip().lower() != "yes":
            print("Nothing changed.")
            return
    username = input("Choose a username: ").strip()
    if len(username) < 3:
        print("The username must be at least 3 characters.")
        return
    password = getpass.getpass(f"Choose a password (at least {auth.MIN_PASSWORD} characters): ")
    if len(password) < auth.MIN_PASSWORD:
        print(f"The password must be at least {auth.MIN_PASSWORD} characters.")
        return
    if password != getpass.getpass("Type the password again: "):
        print("The passwords did not match. Nothing was saved.")
        return
    auth.save_credentials(username, password)
    print("Saved. You can now start the dashboard and sign in.")


if __name__ == "__main__":
    main()
