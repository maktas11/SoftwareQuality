from typing import Callable, Tuple

import getpass


def prompt_text(label: str) -> str:
    return input(label).strip()


def prompt_password(label: str) -> str:
    return getpass.getpass(label).strip()


def prompt_until_valid(
    label: str,
    validator: Callable[[str], Tuple[bool, str]],
    allow_empty: bool = False,
    hint: str = "",
) -> str:
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
