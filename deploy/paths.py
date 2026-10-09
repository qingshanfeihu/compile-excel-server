"""安装登记与向导草稿放在哪里（ces 与 ces setup 共用）。"""

from __future__ import annotations

import os
import sys
from pathlib import Path


def config_root() -> Path:
    """~/.config/compile-excel-server（Windows：%APPDATA%）；CES_CONFIG_ROOT 可改。

    用 sudo 运行时（例如 sudo ces service install），HOME 会被换成 root 的，这里改回发起 sudo 的
    那个用户的目录，否则找不到他的安装登记。"""
    override = os.environ.get("CES_CONFIG_ROOT")
    if override:
        return Path(override)
    if os.name == "nt" and os.environ.get("APPDATA"):
        return Path(os.environ["APPDATA"]) / "compile-excel-server"
    home = Path.home()
    sudo_user = os.environ.get("SUDO_USER") or ""
    if sudo_user and hasattr(os, "geteuid") and os.geteuid() == 0:
        try:
            import pwd

            home = Path(pwd.getpwnam(sudo_user).pw_dir)
        except (ImportError, KeyError):
            pass
    return home / ".config" / "compile-excel-server"


def system_env() -> dict[str, str]:
    """调用系统程序（curl、bash、systemctl、launchctl）用的环境变量。

    打包后的程序启动时会把 LD_LIBRARY_PATH 指向自带的库，原值存在 LD_LIBRARY_PATH_ORIG；
    原样传给系统程序可能让它加载到包里的 libssl 而起不来，这里换回原值。"""
    env = dict(os.environ)
    for name in ("LD_LIBRARY_PATH", "DYLD_LIBRARY_PATH"):
        original = env.pop(f"{name}_ORIG", None)
        if original is not None:
            env[name] = original
        elif getattr(sys, "frozen", False):
            env.pop(name, None)
    return env
