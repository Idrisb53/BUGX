
from dataclasses import dataclass, replace
from typing import Optional

from bugx.core.runner import ToolRunner


# =========================================================
# TOOL INFORMATION
# =========================================================

@dataclass
class ToolInfo:
    name: str
    category: str
    purpose: str
    commands: tuple
    installed: bool = False
    executable: Optional[str] = None
    key: str = ""
    version: str = ""
    status: str = ""
    message: str = ""
    install_hint: str = ""


# =========================================================
# BUGX TOOL REGISTRY
# Built from the module adapter registries (10 tools each)
# plus manual/external integrations.
# =========================================================

CATEGORY_TITLES = {
    "recon": "Recon",
    "enumeration": "Enumeration",
    "vulnerability_analysis": "Vulnerability Analysis",
}


def all_adapters() -> list:
    """Every registered tool adapter, in module order."""
    from bugx.modules.analysis.registry import ANALYSIS_ADAPTERS
    from bugx.modules.enumeration.registry import ENUMERATION_ADAPTERS
    from bugx.modules.recon.registry import RECON_ADAPTERS

    return [*RECON_ADAPTERS, *ENUMERATION_ADAPTERS, *ANALYSIS_ADAPTERS]


def _build_registry() -> list:
    registry = [
        ToolInfo(
            adapter.name,
            CATEGORY_TITLES.get(adapter.module, adapter.module),
            adapter.purpose,
            tuple(adapter.binaries),
            key=adapter.key,
        )
        for adapter in all_adapters()
    ]
    registry += [
        ToolInfo("Burp Suite", "External", "Manual web security testing", ()),
        ToolInfo("Wappalyzer", "External", "Technology identification", ()),
        ToolInfo("GitHub Search", "External", "Public source code research", ()),
    ]
    return registry


TOOL_REGISTRY = _build_registry()


# =========================================================
# TOOL MANAGER
# =========================================================

class ToolManager:
    """
    Central tool detection and execution manager for BUGX.
    """

    def __init__(self):
        # Copy registry entries to avoid modifying global objects.
        self.tools = [
            replace(tool) for tool in TOOL_REGISTRY
        ]

    # -----------------------------------------------------
    # CHECK SINGLE TOOL
    # -----------------------------------------------------

    def check_tool(self, tool: ToolInfo) -> ToolInfo:

        tool.installed = False
        tool.executable = None

        for command in tool.commands:

            executable = ToolRunner.get_path(command)

            if executable:
                tool.installed = True
                tool.executable = executable
                break

        return tool

    # -----------------------------------------------------
    # CHECK ALL TOOLS
    # -----------------------------------------------------

    def check_all(self) -> list:

        return [
            self.check_tool(tool)
            for tool in self.tools
        ]

    # -----------------------------------------------------
    # DETAILED CHECK (version, configuration, binary identity)
    # -----------------------------------------------------

    def check_all_detailed(self, settings: Optional[dict] = None) -> list:
        adapters = {adapter.key: adapter for adapter in all_adapters()}
        checked = []
        for tool in self.tools:
            adapter = adapters.get(tool.key)
            if adapter is None:
                tool.status = "External"
                checked.append(tool)
                continue
            status = adapter.status(settings or {})
            tool.installed = status.status == "Installed"
            tool.executable = status.executable
            tool.version = status.version
            tool.status = status.status
            tool.message = status.message
            tool.install_hint = status.install_hint
            checked.append(tool)
        return checked

    # -----------------------------------------------------
    # GET TOOL BY NAME
    # -----------------------------------------------------

    def get_tool(self, name: str) -> Optional[ToolInfo]:

        for tool in self.tools:

            if tool.name.lower() == name.lower():
                return self.check_tool(tool)

        return None

    # -----------------------------------------------------
    # INSTALLED TOOLS
    # -----------------------------------------------------

    def get_installed(self) -> list:

        return [
            tool
            for tool in self.check_all()
            if tool.commands and tool.installed
        ]

    # -----------------------------------------------------
    # MISSING TOOLS
    # -----------------------------------------------------

    def get_missing(self) -> list:

        return [
            tool
            for tool in self.check_all()
            if tool.commands and not tool.installed
        ]

    # -----------------------------------------------------
    # EXTERNAL TOOLS
    # -----------------------------------------------------

    def get_external(self) -> list:

        return [
            tool
            for tool in self.tools
            if tool.category.lower() == "external"
        ]

    # -----------------------------------------------------
    # SYSTEM SUMMARY
    # -----------------------------------------------------

    def summary(self) -> dict:

        checked = self.check_all()

        detectable = [
            tool for tool in checked
            if tool.commands
        ]

        installed = [
            tool for tool in detectable
            if tool.installed
        ]

        missing = [
            tool for tool in detectable
            if not tool.installed
        ]

        external = self.get_external()

        return {
            "total": len(checked),
            "detectable": len(detectable),
            "installed": len(installed),
            "missing": len(missing),
            "external": len(external),
        }

    # -----------------------------------------------------
    # RUN TOOL
    # -----------------------------------------------------

    def run(
        self,
        name: str,
        args: list,
        timeout: int = 180,
    ):

        tool = self.get_tool(name)

        if tool is None:
            raise ValueError(
                f"BUGX: Tool '{name}' is not registered."
            )

        if not tool.commands:
            raise RuntimeError(
                f"BUGX: {name} requires external/manual integration."
            )

        if not tool.installed:
            raise FileNotFoundError(
                f"BUGX: {name} is not installed."
            )

        return ToolRunner.run(
            tool.commands[0],
            args,
            timeout=timeout,
        )
