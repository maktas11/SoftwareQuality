from typing import Callable, Tuple

import getpass

# --- UI input layer (separation of concerns) ---
# Input collection is separated from validation logic.
# This module only handles reading from the user and looping on bad input.
# The actual validation rules live in core/validation.py.
# This separation means the validation logic can be tested independently
# and reused if we ever switch to a GUI or web interface.


def prompt_text(label: str) -> str:
    # .strip() removes leading/trailing whitespace to prevent accidental
    # spaces from messing up validation or database lookups.
    return input(label).strip()


def prompt_password(label: str) -> str:
    # getpass hides the password as the user types — prevents shoulder surfing.
    # This is a basic but important security measure for a console app.
    return getpass.getpass(label).strip()


def prompt_until_valid(
    label: str,
    validator: Callable[[str], Tuple[bool, str]],
    allow_empty: bool = False,
    hint: str = "",
) -> str:
    # Keeps asking until the input passes the validator function.
    # Invalid input never makes it past this point — the validation layer
    # acts as a gatekeeper before any data reaches the service/database layer.
    shown_hint = False
    while True:
        if hint and not shown_hint:
            print(f"Hint: {hint}")
            shown_hint = True
        value = input(label)
        if allow_empty and value == "":
            return value
        ok, msg = validator(value)
        if ok:
            return value
        if hint:
            print(f"Invalid input: {msg}. Hint: {hint}")
        else:
            print(f"Invalid input: {msg}")


def prompt_password_until_valid(
    label: str,
    validator: Callable[[str], Tuple[bool, str]],
    hint: str = "",
) -> str:
    # Same loop as prompt_until_valid but uses getpass for masked input.
    # Password is validated in memory and never printed back to the screen.
    shown_hint = False
    while True:
        if hint and not shown_hint:
            print(f"Hint: {hint}")
            shown_hint = True
        value = getpass.getpass(label)
        ok, msg = validator(value)
        if ok:
            return value
        if hint:
            print(f"Invalid input: {msg}. Hint: {hint}")
        else:
            print(f"Invalid input: {msg}")


def prompt_choice(label: str, options: dict) -> str:
    while True:
        value = input(label).strip()
        if value in options:
            return options[value]
        upper = value.upper()
        if upper in options:
            return options[upper]
        print("Invalid choice.")
