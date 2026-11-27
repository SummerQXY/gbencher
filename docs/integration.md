# 在 Python Web 服务中调用 gbench

`gbench` 是只读扫描 CLI。Web 服务负责身份授权、任务调度、报告保存和历史状态；扫描器只接收命令参数与可选的 profile 输入，并输出一次扫描的 JSON。调用方应固定二进制、内置规则和随附 schema 的版本。

## 运行边界

- 用 argv 数组启动二进制，不经 shell。每次任务创建独立进程；至少传一个 `--project=<id>`，指定 `--format=json`。可用 `--rule`、`--exclude`、`--profile=-` 和 `--set` 收窄范围或覆盖受约束的参数。
- profile 可从 stdin 传 YAML 或 JSON。`--profile=-` 时必须提供非空内容；其他文件路径由调用方控制。不要把凭据、access token 或扫描数据写入 profile。
- 为每次任务设置独立的 `CLOUDSDK_CONFIG`，把需要的代理等 gcloud 属性配置在其中。引擎对子进程环境使用正向清单，绝大多数 `CLOUDSDK_*` 变量不会透传；不要依赖它们设置账号、端点或配额项目。扫描结束后由调用方清理该目录。`--account`、`--impersonate-service-account` 和 `--quota-project` 若使用，应由可信的任务配置给出，并在报告的 `scan.identity` 中核对。
- `--quota-project` 是可选项，调用方无需把它设为必填，也无需让配额项目与扫描目标相同。显式传入时，扫描身份需要对该项目具备 `serviceusage.services.use`；缺失时连项目元数据预检也可能失败。不传时扫描器不注入 `--billing-project`，gcloud 使用其配置的 `billing/quota_project`（未配置时 SDK 默认当前 project），而报告中的 `scan.identity.quota_project` 为 null，并不记录 gcloud 的默认值。调用方应另行核对实际配额归属；不能因为预检失败就默默移除该 flag，让未获准的默认 quota project 承担请求。
- gbench 不自动写扫描数据。stdout 与 stderr 可能包含账号、资源名及其他敏感值，调用方须限制访问并控制保留期限。只有显式 `--output=<path>` 会写规范报告：目标文件权限为 0600，先写同目录临时文件再原子发布；已存在时拒绝，`--force` 才覆盖。中断时不发布该文件。
- 在实际扫描前，可用 `scan --dry-run --format=json` 检查规则、作用域、能力缺口及首层命令；此命令不调用 gcloud、kubectl 或 REST。`auth check --project=<id> --format=json` 会执行只读预检，不能当作 dry-run。

## Python 调用示例

下面示例使用 stdout，不创建报告文件。`schema_path` 必须指向**与执行的 gbench 二进制同一发布版本**的 `schemas/report.schema.json`。

```python
import json
import os
import signal
import subprocess
from pathlib import Path
from typing import Optional, Tuple

from jsonschema import Draft202012Validator, FormatChecker


def scan_project(binary: Path, schema_path: Path, config_dir: Path, project_id: str, profile: bytes, quota_project: Optional[str] = None) -> Tuple[int, Optional[dict]]:
    argv = [str(binary), "scan", f"--project={project_id}", "--profile=-", "--format=json"]
    if quota_project is not None:
        argv.append(f"--quota-project={quota_project}")
    env = os.environ.copy()
    env["CLOUDSDK_CONFIG"] = str(config_dir)
    process = subprocess.Popen(
        argv,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=env,
        start_new_session=True,
    )
    try:
        stdout, stderr = process.communicate(input=profile, timeout=900)
    except subprocess.TimeoutExpired:
        os.killpg(process.pid, signal.SIGTERM)
        try:
            process.communicate(timeout=10)
        except subprocess.TimeoutExpired:
            os.killpg(process.pid, signal.SIGKILL)
            process.communicate()
        raise

    if process.returncode not in (0, 1, 4):
        # Record stderr only in a protected operational log after redaction and size limiting.
        return process.returncode, None

    report = json.loads(stdout)
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    Draft202012Validator(schema, format_checker=FormatChecker()).validate(report)
    return process.returncode, report
```

生产调用方还应给 stdout、stderr 和输入 profile 设置大小限制，并在取消任务时向整个进程组发 SIGTERM，超时后再发 SIGKILL。示例只展示同步调用与基本超时处理，不代替任务队列的资源限制和保密存储。

## 退出码和报告

| 退出码 | 处理方式 | 报告 |
|---|---|---|
| 0 | 扫描完成，未命中 `--fail-on` | 有 |
| 1 | 扫描完成，命中 `--fail-on` | 有 |
| 2 | 参数、profile 或规则校验错误 | 无 |
| 3 | 无法运行，例如缺凭据、gcloud 不可用、目标无法解析或文件发布失败 | 无 |
| 4 | 扫描运行，但没有任何 unit 成功评估 | 有，必须展示缺口 |
| 130 / 143 | SIGINT / SIGTERM 中断 | 无，`--output` 不发布 |

默认 `--fail-on=fail,error`。退出码 1 不代表所有结果均不合规；应读取逐项状态。退出码 4 独立于 `--fail-on`。对于 `--output`，退出码 0、1、4 均可发布报告；调用方须在成功返回后读取目标文件。

保存报告时，将 `scan.id`、`scan.tool.version`、`scan.tool.ruleset_hash`、`scan.selection.profile_hash` 与报告关联存储。目录可用 `rules list --format=json` 获取，必须与报告的规则集版本配对。

## Schema 和版本

报告 schema 使用 `additionalProperties: false`。同一主版本的 minor 更新可能新增字段或枚举值，因此旧 schema 也会拒绝新版本报告；使用与产出报告的 gbench **同版本附带的** `schemas/report.schema.json`，并把二进制与 schema 一起固定版本。若消费端要兼容更新的 minor 版本，应只校验必需结构，并容忍未知字段与未知枚举值；不能继续用旧的严格 schema 声称新报告无效。

Python `jsonschema` 对以 `$` 结尾的正则可能接受末尾换行，而 Go 的 RE2 不接受；这会使 Python 侧校验略宽。扫描器自身生成的报告不受该差异影响。

## 解释扫描结果

- 展示 `scan.status` 和 `scan.coverage`，再展示状态分布。`REVIEW` 不是 `PASS`；低于 `fixture` 的 `verification` 表示合规判定的验证证据较弱。采集错误产生 `SKIPPED` 或 `ERROR`，不能显示为配置 `FAIL`。
- 发现项跨扫描以 `finding_key` 关联，不用报告内 `results[].id`。某个 key 在新报告中缺席时，只有同一规则与目标的 unit 已成功评估（采集 `SUCCEEDED`，结果非 `SKIPPED` / `ERROR`），才可判断为已修复或资源已删除；否则保持原状态并标记未评估。
- cluster 目标缺席时，只有 `scan.targets[].clusters.status` 为 `SUCCEEDED` 且 `names` 不含该集群，才可视为删除；`unreachable` 中的集群属于未评估。
- 资源名、描述、消息、证据值均视为不可信文本，Web 页面渲染时转义。豁免、风险接受、指派和历史由 Web 服务另存，并按 `finding_key` 关联，不写回扫描报告。

## Worker 镜像与维护

Worker 镜像需要 gbench 二进制、同版本 schema、Google Cloud CLI、CA 证书和可写的临时目录；构建 gbench 需要 Go 1.25.6，运行镜像不需要 Go 工具链。默认的 gcloud-only 扫描不需要 kubectl；启用 kubectl 能力的镜像还需 kubectl。镜像应由调用方提供经授权的 gcloud 身份和只读权限，并在部署前用 `auth check` 预检；不要把长期凭据打进镜像。

建议 CODEOWNERS 至少覆盖 `rules/`、`rules/allowlist.yaml`、`internal/plan/`、`internal/auth/`、`internal/collect/`、`schemas/` 和 `docs/integration.md`，由规则负责人及安全负责人共同评审规则范围、命令白名单和报告契约的变更。
