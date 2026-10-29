from types import SimpleNamespace

import pytest

from tiled.client.context import identity_provider_input

PROVIDERS = [SimpleNamespace(provider="a"), SimpleNamespace(provider="b")]


def answer(monkeypatch, *replies):
    replies = iter(replies)
    monkeypatch.setattr("builtins.input", lambda prompt: next(replies))


def test_choice_selects_provider(monkeypatch):
    answer(monkeypatch, "1")
    assert identity_provider_input(PROVIDERS).provider == "a"


@pytest.mark.parametrize("bad", ["x", "0", "3"])
def test_invalid_choice_prompts_again(monkeypatch, bad):
    answer(monkeypatch, bad, "1")
    assert identity_provider_input(PROVIDERS).provider == "a"


def test_empty_choice_cancels(monkeypatch):
    answer(monkeypatch, "")
    with pytest.raises(RuntimeError, match="No authentication provider chosen"):
        identity_provider_input(PROVIDERS)
