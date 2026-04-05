"""Base skill class for enterprise AI agent skills."""

import logging
from abc import ABC, abstractmethod
from typing import Any


class BaseSkill(ABC):
    """Abstract base class for all agent skills.

    Skills are the atomic, reusable capabilities that agents compose to
    accomplish their tasks.  Each skill wraps a single cybersecurity tool
    or API call and returns a structured result dictionary.
    """

    def __init__(self, name: str, description: str) -> None:
        self.name = name
        self.description = description
        self.logger = logging.getLogger(self.__class__.__name__)

    @abstractmethod
    def execute(self, **kwargs: Any) -> dict[str, Any]:
        """Execute the skill.

        Keyword arguments vary per skill – see each subclass for details.

        Returns:
            A dictionary containing at minimum:
            - ``"skill"``: the skill name
            - ``"status"``: ``"success"`` or ``"error"``
            - ``"result"``: the task output (type varies per skill)
        """

    def __call__(self, **kwargs: Any) -> dict[str, Any]:
        """Allow skills to be invoked directly as callables."""
        return self.execute(**kwargs)

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}(name={self.name!r})"
