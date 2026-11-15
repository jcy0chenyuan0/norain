"""代理模块：负责转发的核心——一个被监督的 sing-box 进程。

转发本身由 sing-box 完成（不重复造轮子）；本模块把共享的监督器（norain_core.supervisor）
包成可以由内控制模块启动、停止、重启的组件。监督器自己负责 sing-box 崩溃后的有限次重启，
超过上限后本模块进入 failed 状态，由自维持模块接手（修复 → 阻断）。
"""

from __future__ import annotations

import threading
import time
from typing import Callable

from norain_core.errors import EXIT_OK
from norain_core.state import read_json
from norain_core.supervisor import STOP_GRACE_SECONDS, Spec, Supervisor


class ProxyModule:
    name = "proxy"

    def __init__(self, spec_fn: Callable[[], Spec]) -> None:
        self._spec_fn = spec_fn
        self.spec: Spec | None = None
        self.sup: Supervisor | None = None
        self.exit_code: int | None = None
        self.started_at: float | None = None
        self._thread: threading.Thread | None = None
        self._lifetime_restarts = 0

    def _run(self, sup: Supervisor) -> None:
        try:
            self.exit_code = sup.run()
        except Exception:  # noqa: BLE001 监督器自身异常按故障处理
            self.exit_code = 1
        finally:
            self._lifetime_restarts += sup.total_restarts

    def start(self) -> None:
        if self.alive():
            return
        self.spec = self._spec_fn()
        self.sup = Supervisor(self.spec)
        self.exit_code = None
        self.started_at = time.time()
        self._thread = threading.Thread(target=self._run, args=(self.sup,), name="norain-proxy", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        if self.sup is not None:
            self.sup.request_stop()
        if self._thread is not None:
            self._thread.join(STOP_GRACE_SECONDS + 10)

    def alive(self) -> bool:
        return bool(self._thread and self._thread.is_alive())

    @property
    def failed(self) -> bool:
        """监督器已经放弃（达到连续重启上限或自身出错）。"""
        return not self.alive() and self.exit_code not in (None, EXIT_OK)

    @property
    def child_pid(self) -> int | None:
        return self.sup.child_pid if self.sup is not None and self.alive() else None

    @property
    def ready(self) -> bool:
        """sing-box 在运行，并且所有本地端口都已开始监听。"""
        # 直接问监督器（同一进程里的对象）：这个属性每秒被读很多次，不值得每次读状态文件再查进程表
        sup = self.sup
        return bool(sup is not None and self.alive() and sup.ready and sup.child_pid is not None)

    @property
    def restarts(self) -> int:
        return self._lifetime_restarts + (self.sup.total_restarts if self.sup and self.alive() else 0)

    def wait_ready(self, timeout: float) -> bool:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if self.ready:
                return True
            if self.failed:
                return False
            time.sleep(0.2)
        return self.ready

    def status(self) -> dict:
        state = "running" if self.ready else "starting" if self.alive() else "failed" if self.failed else "stopped"
        return {"state": state, "pid": self.child_pid, "restarts": self.restarts,
                "exit_code": self.exit_code,
                "last_result": read_json(self.spec.last_error_file) if self.spec and self.failed else None}
