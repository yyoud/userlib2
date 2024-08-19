from typing import Optional


class _Error(Exception):
    def __init__(self, message: Optional[str] = None):
        self.message = message
        super().__init__(self.message)

# what's the difference between the thing above and below


class CoreError(Exception):
    pass


class FuckOffError(_Error):
    """tells you to fuck off. if you want something work for it."""
    pass


class BullShitError(_Error):
    """stop fucking bullshitting me douche"""
    pass


if __name__ == "__main__":
    raise _Error("clone")

