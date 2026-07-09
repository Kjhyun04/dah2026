"""core.modules.sidecar — SidecarManager: 장수 툴링 사이드카 수명관리 + container_of 리졸버.

역할(13 §2·§3 · R2 · 09 종료계약):
  · container_of(sidecar) — 사이드카 리터럴(ue/core/sgi) -> **우리 소유** 장수 사이드카
    컨테이너 이름. 순수·결정론(docker 무접속) -> LocalBackend.container_of 주입점.
  · ensure(kind)/ensure_all — 우리 라벨(dah_safeexec=attack_agent) 사이드카가 있으면 **재사용**,
    없으면 `docker run -d --label … --network …`(attacker_ue netns 공유/net 연결) 기동.
    모든 docker 발화는 **backend.run(on_host) 경유**(직접 subprocess 금지 · 종료계약 일관).
      이 워크플로우는 완전 오프라인 -> ensure/teardown 은 로컬 dry-run 에서 **호출하지 않는다**
      (실기동은 사람 런북). 코드는 커맨드 조립 + 파서만 제공.
  · teardown — 우리 라벨 사이드카 `docker rm -f`(원자 회수·FACT4 · R2). backend 경유.

불변식:
  하드코딩0 : 이미지/네트워크/벤티지 컨테이너명은 전부 config(InputSpec) 주입.
              name_prefix/라벨/`sleep infinity` CMD 는 상수(IP/컨테이너명 아님).
  R2 라벨   : safeexec.LABEL_KEY=LABEL_VALUE 재사용 -> reap_labeled 정본과 동일 라벨로 회수.
  종료계약  : `docker run --rm` 금지 · compose --remove-orphans 금지 · 넓은 kill 금지 ·
              대상 stop/terminate 금지. 사이드카 CMD=`sleep infinity`(장수) + `docker exec`.
작성 2026-07-06.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from core.modules.backends import (
    Backend,
    CRSError,
    Err,
    ExecOutput,
    ExecRequest,
    Ok,
    Result,
)

# R2 라벨 정본은 safeexec 소유(atexit reap_labeled 와 동일 라벨로 회수되도록 재사용).
from core.modules.safeexec import LABEL_KEY, LABEL_VALUE

# ═══════════════════════════════════════════════════════════════════════════
# 0. 상수 — 우리 소유 식별(이름 접두 · per-kind 라벨) · 장수 CMD (하드코딩 아님)
# ═══════════════════════════════════════════════════════════════════════════

_NAME_PREFIX = "dah_tools"       # 사이드카 컨테이너 이름 접두(우리 소유 식별). IP/대상명 아님.
_KIND_LABEL = "dah_sidecar_kind"  # per-kind 조회 라벨 키(재사용 필터). 값=kind.
_SLEEP_CMD: tuple[str, ...] = ("sleep", "infinity")  # 장수 사이드카 CMD(13 §2 · README).


# ═══════════════════════════════════════════════════════════════════════════
# 1. SidecarSpec — kind 1종의 기동 규격 (전부 config 주입값에서 파생)
# ═══════════════════════════════════════════════════════════════════════════


@dataclass(frozen=True, slots=True)
class SidecarSpec:
    """사이드카 kind 1종 기동 규격.

    kind        : 실행 발판 리터럴(ue/core/sgi). host 는 사이드카 없음(미포함).
    image       : 툴링 이미지(config.tools.image.air|pfcp — 하드코딩 0).
    network     : 벤티지 네트워크/컨테이너 값(config.exec.vantage.<kind> — 하드코딩 0).
    netns_share : True -> `--network container:<network>`(대상 netns 공유, 예 attacker_ue) ·
                  False -> `--network <network>`(net 연결, 예 net_sgi). 13 §3 벤티지 모델.
    """

    kind: str
    image: str
    network: str
    netns_share: bool


# ═══════════════════════════════════════════════════════════════════════════
# 2. SidecarManager — 재사용/기동/회수 + container_of 리졸버
# ═══════════════════════════════════════════════════════════════════════════


class SidecarManager:
    """장수 툴링 사이드카 수명관리자. LocalBackend 에 container_of 로 주입.

    specs      : kind -> SidecarSpec(config 파생). ue/sgi/(core) 등.
    docker_bin : docker CLI(하드코딩 0 · 주입 가능).
    name_prefix: 사이드카 컨테이너 이름 접두(우리 소유 식별).
    backend    : ensure/teardown docker 발화를 태울 실행 백엔드(on_host). 미바인딩 시
                 container_of(순수 해석)만 가능하고 ensure/teardown 은 no-op/Err(오프라인).

    container_of 는 **순수 함수**(docker 무접속) — 오프라인 recon-only 에서도 backend 가
      사이드카 exec 대상을 결정론적으로 해석할 수 있게 한다(실기동은 런북 ensure).
    """

    def __init__(
        self,
        *,
        specs: list[SidecarSpec],
        docker_bin: str = "docker",
        name_prefix: str = _NAME_PREFIX,
        backend: Optional[Backend] = None,
    ) -> None:
        self._specs: dict[str, SidecarSpec] = {s.kind: s for s in specs}
        self._docker = docker_bin
        self._prefix = name_prefix
        self._backend = backend

    # ── backend 바인딩(구성 순서: mgr -> backend(container_of=mgr) -> mgr.bind_backend) ──
    def bind_backend(self, backend: Backend) -> None:
        """ensure/teardown docker 발화용 백엔드 주입(구성 사이클 회피). 재바인딩 허용."""
        self._backend = backend

    @property
    def kinds(self) -> list[str]:
        return sorted(self._specs)

    def _spec(self, kind: str) -> SidecarSpec:
        s = self._specs.get(kind)
        if s is None:
            raise CRSError(
                f"sidecar: no spec for kind {kind!r}",
                extra={"known": self.kinds},
            )
        return s

    # ── container_of 리졸버(순수·결정론 — LocalBackend 주입점) ─────────────
    def container_of(self, sidecar: str) -> str:
        """사이드카 리터럴 -> **우리 소유** 장수 사이드카 컨테이너 이름(결정론).

        host 는 사이드카 없음(LocalBackend 는 on_host 분기라 호출 안 됨) -> CRSError.
        이름은 `<prefix>_<kind>`(우리 접두) — 벤티지 대상(attacker_ue 등)이 아니라 그 netns
        를 공유하는 **툴링 사이드카** 이름이다(13 §2).
        """
        self._spec(sidecar)  # 미정의 kind -> CRSError(닫힘)
        return f"{self._prefix}_{sidecar}"

    # ── 커맨드 조립(순수 · 코드만 — 실행은 backend.run(on_host) 또는 런북) ──
    def _network_arg(self, spec: SidecarSpec) -> str:
        return f"container:{spec.network}" if spec.netns_share else spec.network

    def run_argv(self, kind: str) -> tuple[str, ...]:
        """`docker run -d --name … --label … --network … <image> sleep infinity` 조립.

        금지 회피: `--rm` 없음(장수 사이드카) · ENTRYPOINT 자동공격 없음(CMD=sleep infinity)
          · compose 미사용. 라벨은 우리 것(R2 회수 조준) + per-kind(재사용 필터).
        """
        spec = self._spec(kind)
        return (
            self._docker,
            "run",
            "-d",
            "--name",
            self.container_of(kind),
            "--label",
            f"{LABEL_KEY}={LABEL_VALUE}",
            "--label",
            f"{_KIND_LABEL}={kind}",
            "--network",
            self._network_arg(spec),
            "--restart",
            "no",
            spec.image,
            *_SLEEP_CMD,
        )

    def exists_argv(self, kind: str) -> tuple[str, ...]:
        """우리 라벨 + 이름 완전일치로 사이드카 존재 조회(`docker ps -aq --filter …`)."""
        name = self.container_of(kind)
        return (
            self._docker,
            "ps",
            "-aq",
            "--filter",
            f"label={LABEL_KEY}={LABEL_VALUE}",
            "--filter",
            f"name=^{name}$",
        )

    def reap_ls_argv(self) -> tuple[str, ...]:
        """우리 라벨 사이드카 전량 id 조회(teardown 1단계)."""
        return (
            self._docker,
            "ps",
            "-aq",
            "--filter",
            f"label={LABEL_KEY}={LABEL_VALUE}",
        )

    # ── 실행 헬퍼(전부 backend.run(on_host) 경유 — 직접 subprocess 금지) ────
    async def _run_host(
        self, argv: tuple[str, ...], *, tool_id: str
    ) -> Result[ExecOutput]:
        """host 벤티지 docker CLI 발화(on_host). 예외 누출 금지(Result 봉투)."""
        if self._backend is None:
            return Err(
                CRSError(
                    "sidecar: backend not bound (offline — ensure/teardown 무실행)",
                    extra={"tool": tool_id},
                )
            )
        req = ExecRequest(
            sidecar="host", argv=argv, on_host=True, tool_id=tool_id
        )
        try:
            return await self._backend.run(req)
        except CRSError as e:
            return Err(e)
        except Exception as e:  # noqa: BLE001
            return Err(
                CRSError(
                    f"sidecar host run failed: {type(e).__name__}",
                    extra={"tool": tool_id},
                )
            )

    # ── ensure(재사용 or 기동) ────────────────────────────────────────────
    async def ensure(self, kind: str) -> Result[str]:
        """우리 라벨 사이드카 재사용 or `docker run -d` 기동 -> 컨테이너 이름.

        오프라인 무실행: 이 메서드는 backend 가 실 docker 에 닿을 때만 유효(런북 gate).
          로컬 dry-run 은 호출하지 않는다(container_of 순수 해석만 사용).
        """
        try:
            name = self.container_of(kind)
        except CRSError as e:
            return Err(e)

        # (1) 재사용: 우리 라벨 + 이름으로 이미 있으면 그대로.
        match await self._run_host(self.exists_argv(kind), tool_id=f"sidecar:ps:{kind}"):
            case Err() as e:
                return e
            case Ok(out):
                if out.stdout.strip():
                    return Ok(name)

        # (2) 기동: `docker run -d --label … --network … sleep infinity`(코드만).
        match await self._run_host(
            self.run_argv(kind), tool_id=f"sidecar:run:{kind}"
        ):
            case Err() as e:
                return e
            case Ok(out):
                if out.returncode != 0:
                    return Err(
                        CRSError(
                            f"sidecar run failed: {kind} (rc={out.returncode})",
                            extra={"kind": kind},
                        )
                    )
        return Ok(name)

    async def ensure_all(self) -> Result[dict[str, str]]:
        """정의된 전 kind 사이드카 보장 -> {kind: name}. 하나라도 실패 시 첫 Err."""
        out: dict[str, str] = {}
        for kind in self.kinds:
            match await self.ensure(kind):
                case Err() as e:
                    return e
                case Ok(name):
                    out[kind] = name
        return Ok(out)

    # ── teardown(우리 라벨 원자 회수 · R2 · FACT4) ────────────────────────
    async def teardown(self) -> Result[None]:
        """우리 라벨 사이드카 전량 `docker rm -f`(원자·멱등). backend 미바인딩 시 no-op.

        캠페인 종료 회수의 정본(FACT4): 라벨 사이드카 rm -f 하면 컨테이너 내부 모든
          프로세스가 원자적으로 회수된다. LocalBackend.per-job PGID reap 은 그 상보.
          우리 라벨만 조준(다른 소유 컨테이너 불가침) — 넓은 회수 금지.
        """
        if self._backend is None:
            return Ok(None)  # 오프라인/미바인딩: best-effort no-op

        match await self._run_host(self.reap_ls_argv(), tool_id="sidecar:reap:ls"):
            case Err() as e:
                return e
            case Ok(out):
                ids = [x for x in out.stdout.split() if x]
        if not ids:
            return Ok(None)
        argv = (self._docker, "rm", "-f", *ids)
        match await self._run_host(argv, tool_id="sidecar:reap:rm"):
            case Err() as e:
                return e
            case Ok(_):
                return Ok(None)


__all__ = ["SidecarSpec", "SidecarManager"]
