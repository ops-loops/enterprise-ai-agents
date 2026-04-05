"""Tests for BaseAgent and BaseSkill."""

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pytest
from agents.base_agent import BaseAgent
from skills.base_skill import BaseSkill


# ---------------------------------------------------------------------------
# Minimal concrete implementations for testing
# ---------------------------------------------------------------------------

class _EchoSkill(BaseSkill):
    def __init__(self, name: str = "echo") -> None:
        super().__init__(name=name, description="Echo skill")

    def execute(self, **kwargs):
        return {"skill": self.name, "status": "success", "result": kwargs}


class _DoubleSkill(BaseSkill):
    def __init__(self) -> None:
        super().__init__(name="double", description="Double skill")

    def execute(self, value: int = 0, **kwargs):
        return {"skill": self.name, "status": "success", "result": value * 2}


class _ConcreteAgent(BaseAgent):
    def run(self, **kwargs):
        return {"agent": self.name, "status": "success", "result": kwargs}


# ---------------------------------------------------------------------------
# BaseSkill tests
# ---------------------------------------------------------------------------

class TestBaseSkill:
    def test_repr(self):
        skill = _EchoSkill()
        assert "EchoSkill" in repr(skill)
        assert "echo" in repr(skill)

    def test_callable(self):
        skill = _EchoSkill()
        result = skill(msg="hello")
        assert result["status"] == "success"
        assert result["result"]["msg"] == "hello"

    def test_execute(self):
        skill = _EchoSkill()
        result = skill.execute(x=1)
        assert result["skill"] == "echo"


# ---------------------------------------------------------------------------
# BaseAgent tests
# ---------------------------------------------------------------------------

class TestBaseAgent:
    def _make_agent(self):
        return _ConcreteAgent(name="test_agent", description="A test agent")

    def test_repr(self):
        agent = self._make_agent()
        assert "ConcreteAgent" in repr(agent)

    def test_register_skill(self):
        agent = self._make_agent()
        skill = _EchoSkill()
        agent.register_skill(skill)
        assert "echo" in agent.skills

    def test_register_duplicate_skill_raises(self):
        agent = self._make_agent()
        agent.register_skill(_EchoSkill())
        with pytest.raises(ValueError, match="already registered"):
            agent.register_skill(_EchoSkill())

    def test_register_non_skill_raises(self):
        agent = self._make_agent()
        with pytest.raises(TypeError):
            agent.register_skill("not_a_skill")  # type: ignore[arg-type]

    def test_get_skill(self):
        agent = self._make_agent()
        skill = _EchoSkill()
        agent.register_skill(skill)
        assert agent.get_skill("echo") is skill

    def test_get_missing_skill_raises(self):
        agent = self._make_agent()
        with pytest.raises(KeyError):
            agent.get_skill("nonexistent")

    def test_skills_property_is_copy(self):
        agent = self._make_agent()
        agent.register_skill(_EchoSkill())
        snapshot = agent.skills
        agent.register_skill(_DoubleSkill())
        # snapshot should not see the new skill
        assert "double" not in snapshot

    def test_run(self):
        agent = self._make_agent()
        result = agent.run(foo="bar")
        assert result["status"] == "success"
        assert result["agent"] == "test_agent"
