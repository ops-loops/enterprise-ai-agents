"""Base agent class for enterprise AI agents."""

import logging
from abc import ABC, abstractmethod
from typing import Any

from skills.base_skill import BaseSkill


class BaseAgent(ABC):
    """Abstract base class for all enterprise AI agents.

    Agents orchestrate one or more :class:`~skills.base_skill.BaseSkill`
    instances to accomplish a high-level cybersecurity task.
    """

    def __init__(self, name: str, description: str) -> None:
        self.name = name
        self.description = description
        self._skills: dict[str, BaseSkill] = {}
        self.logger = logging.getLogger(self.__class__.__name__)

    # ------------------------------------------------------------------
    # Skill registry
    # ------------------------------------------------------------------

    def register_skill(self, skill: BaseSkill) -> None:
        """Register a skill with this agent.

        Args:
            skill: A :class:`~skills.base_skill.BaseSkill` instance to add.

        Raises:
            TypeError: If *skill* is not a :class:`~skills.base_skill.BaseSkill`.
            ValueError: If a skill with the same name is already registered.
        """
        if not isinstance(skill, BaseSkill):
            raise TypeError(f"Expected a BaseSkill instance, got {type(skill)}")
        if skill.name in self._skills:
            raise ValueError(f"Skill '{skill.name}' is already registered with agent '{self.name}'")
        self._skills[skill.name] = skill
        self.logger.debug("Registered skill '%s' on agent '%s'", skill.name, self.name)

    def get_skill(self, skill_name: str) -> BaseSkill:
        """Return a registered skill by name.

        Args:
            skill_name: The unique name of the skill.

        Raises:
            KeyError: If no skill with *skill_name* is registered.
        """
        if skill_name not in self._skills:
            raise KeyError(f"Skill '{skill_name}' is not registered with agent '{self.name}'")
        return self._skills[skill_name]

    @property
    def skills(self) -> dict[str, BaseSkill]:
        """Return a read-only view of registered skills."""
        return dict(self._skills)

    # ------------------------------------------------------------------
    # Execution
    # ------------------------------------------------------------------

    @abstractmethod
    def run(self, **kwargs: Any) -> dict[str, Any]:
        """Execute the agent's primary task.

        Subclasses must implement this method.  It should invoke the
        appropriate skills and return a structured result dictionary.

        Returns:
            A dictionary containing at minimum:
            - ``"agent"``: the agent name
            - ``"status"``: ``"success"`` or ``"error"``
            - ``"result"``: the task output (type varies per agent)
        """

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}(name={self.name!r}, skills={list(self._skills)})"
