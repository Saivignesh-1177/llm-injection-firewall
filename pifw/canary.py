"""Canary tokens catch system-prompt leakage in model *output*.

A random token goes into the system prompt. If it ever shows up in a response,
the prompt leaked, whether or not the input scanner caught the attack.
"""
import secrets


class CanaryVault:
    def __init__(self) -> None:
        self._tokens: dict[str, str] = {}

    def issue(self, session_id: str) -> str:
        token = f"cnry{secrets.token_hex(8)}"
        self._tokens[session_id] = token
        return token

    def leaked(self, session_id: str, model_output: str) -> bool:
        """Catch the token even when the model spaces it out or splits it with punctuation."""
        token = self._tokens.get(session_id)
        if token is None:
            return False
        squashed = "".join(ch for ch in model_output.lower() if ch.isalnum())
        return token in squashed
