# 规则 DSL 参考

本文档是规则文件（`rules/**/*.yaml`、组织自定义规则）的编写契约。引擎实现必须以本文档和 `schemas/rule.schema.json` 为准。

两套语法，边界固定：

- **Go `text/template`**（`{{ .project }}`）只用于渲染字符串：采集命令、API URL、消息。
- **CEL** 只用于逻辑：`resource.from`、`resource.filter`、`resource.name`、`check.assert`、`check.review_when`、`evidence`、`foreach`。

## 1. 文件结构

```yaml
dsl_version: 1
benchmark:
  id: cis-gcp-foundation        # cis-gcp-foundation | cis-gke | 自定义
  version: "5.0.0"
  section: "3"
  title: Networking
rules:
  - id: cis-gcp-3.6
    ...
```

一个文件对应基线的一个章节。每个规则文件必须以 `dsl_version: 1` 开头。自定义规则包可以用任意 `benchmark.id`，但 `rules[].id` 必须全局唯一（跨所有已加载文件）。

## 2. 规则字段

| 字段 | 必填 | 类型 | 说明 |
|---|---|---|---|
| `id` | 是 | string | 全局唯一。内置规则命名：`cis-gcp-<ref>`、`cis-gke-<ref>`。自定义：`<org>-<area>-<nnn>` |
| `ref` | 是 | string | 基线编号，如 `"3.6"`、`"6.2.1"`。字符串，避免 YAML 把 `6.1` 解析为浮点数 |
| `title` | 是 | string | 与基线标题一致，去掉 `(Automated)`/`(Manual)` 后缀 |
| `profile` | 是 | `L1` \| `L2` | 基线 Profile Applicability |
| `cis_assessment` | 是 | `automated` \| `manual` | 基线原标注，只作记录 |
| `mode` | 是 | `deterministic` \| `contextual` | 见第 7 节 |
| `severity` | 是 | `critical` \| `high` \| `medium` \| `low` \| `info` | 本工具的映射，见第 8 节 |
| `scope` | 是 | `project` \| `organization` \| `cluster` | 见第 4 节 |
| `evaluate_per` | `scope: organization` 时必填 | `organization` \| `project` | organization 规则的评估粒度，见 4.1 |
| `services` | 否 | string[] | 采集依赖的 API。任一未启用 → `NOT_APPLICABLE`。若"API 未启用"本身就是不合规（如 2.14），不要在这里声明 |
| `requires` | 否 | string[] | 能力：`kubectl`、`workspace-admin`、`org-access`。不满足 → `SKIPPED` |
| `collect` | `scope: cluster` 时可省略，否则必填 | step[] | 采集步骤，见第 3 节 |
| `resource` | 否 | object | 省略则为聚合规则：整个作用域产生一条结果 |
| `params` | 否 | map | 默认参数；profile 深合并覆盖。值只能是标量、列表、map |
| `params_constraints` | 否 | map | 对可被模板引用的参数加约束（`pattern`、`minimum`、`maximum`、`enum`、`max_length`）。被模板引用的 param 必须是标量并声明约束，lint 强制 |
| `check` | 是 | object | `assert`（必填）、`review_when`、`message`、`review_message` |
| `evidence` | 否 | string[] | CEL 表达式列表，求值结果写入报告；求值失败记为 null，不影响状态 |
| `remediation` | 是 | string | 修复建议，优先给 gcloud / kubectl 命令 |
| `references` | 否 | string[] | URL |
| `notes` | 是 | string | 自动化策略、与基线 Audit 的差异、已知局限、需要调参的说明 |
| `tags` | 否 | string[] | 自由标签 |

## 3. 采集步骤（`collect[]`）

每一步恰好声明一种采集器：`gcloud`、`api`、`kubectl`。

| 字段 | 说明 |
|---|---|
| `id` | 步骤 id，`[a-z][a-z0-9_]*`，在规则内唯一；结果以 `data.<id>` 访问 |
| `gcloud` | `gcloud` 之后的参数串。必须以 `--format=json` 结尾；引擎追加 `--quiet` 并设置 `CLOUDSDK_CORE_DISABLE_PROMPTS=1`。允许的动词与 flag 见 `rules/allowlist.yaml` |
| `api` | `{method, url, body?, paginate?, list_field?, scopes?}`。`method` 只允许 `GET`，或 URL 以 `:getIamPolicy`、`:search`、`:testIamPermissions`、`:getEffectivePolicy`、`:getEffectiveIamPolicy` 结尾的 `POST`。token 来自 `gcloud auth print-access-token`；`scopes` 非空时引擎改用 ADC token（`workspace-admin` 能力）。`paginate: true` 时引擎跟随 `nextPageToken` 并合并 `list_field` 指向的数组，步骤结果即该数组 |
| `kubectl` | `kubectl` 之后的参数串。引擎注入 `--kubeconfig=<临时文件> --context=<当前集群>`。只允许 `get`、`api-resources`、`version`、`auth can-i`；必须 `-o json`（`auth can-i` 除外） |
| `foreach` | CEL 表达式，求值为列表；本步骤对每个元素执行一次。元素在模板中以 `.<as>` 访问（默认 `.item`）。foreach 的来源可以是任意求值为原始数据对象列表的 CEL 表达式（包括 `filter`、`flatten`、列表相加）。结果按对象身份（引用比较）附加到父元素的 `<attach>` 字段（默认为步骤 id），同时 `data.<id>` 为按序的结果列表。在 `attach` 的来源里使用会构造新对象的写法（`map` 宏与 map 字面量）会使该步骤 `ERROR`，lint 也会拒绝。
| `as` | foreach 循环变量名 |
| `attach` | foreach 结果附加到父元素的字段名 |
| `parse` | `json`（默认）\| `text` \| `lines`。`text` 为去掉首尾空白的 stdout 字符串；`lines` 为字符串列表 |
| `on_error` | `error`（默认）\| `empty` \| `skip` \| `ignore`。见下表。`ignore` 表示该步骤是可选的：可忽略的错误会让本步骤视为未执行（`data.<id>` 与 `attach` 字段不存在，报告中记录原因），规则继续评估；权限不足始终为 `SKIPPED`，不受 `ignore` 覆盖 |
| `cross_project` | 布尔，默认 `false`。步骤需要读取其他 project 的资源时（例如 Shared VPC 的宿主 project）设为 `true`，引擎据此放行范围守卫并在 `collectors[]` 标注 |
| `requires` | 步骤级能力；不满足则该步骤跳过，`data.<id>` 与 `attach` 字段都不存在，规则继续评估（配合 `has()` 做降级判定） |

`empty` 的取值由步骤形状决定：`gcloud ... list` 以及带 `list_field` 的 `api` 步骤为 `[]`，其余 `gcloud`/`api`/`kubectl get` 步骤为 `{}`，`parse: text` 为空串，`parse: lines` 为 `[]`。规则作者据此选择 `.?items.orValue([])` 或 `size(...) == 0` 的写法。

`api.url` 可以自带查询参数（如 `?view=FULL`）；分页时引擎用 `&pageToken=` 或 `?pageToken=` 正确拼接。

错误与状态的映射（`on_error` 不能覆盖权限错误，也不能让超时、5xx、输出超限转为空集）：

| 错误类型 | `error`（默认） | `empty` | `skip` | `ignore` |
|---|---|---|---|---|
| API 未启用（SERVICE_DISABLED） | `NOT_APPLICABLE` | 步骤结果为空（`[]` 或 `{}`） | `SKIPPED` | 步骤视为未执行 |
| 权限不足（403 / PERMISSION_DENIED） | `SKIPPED` | `SKIPPED`（`on_error` 不能覆盖） | `SKIPPED` | `SKIPPED` |
| 资源不存在（404 / NOT_FOUND） | `ERROR` | 步骤结果为空 | `SKIPPED` | 步骤视为未执行 |
| 前提不满足（FAILED_PRECONDITION，如产品未开通） | `ERROR` | 步骤结果为空 | `SKIPPED` | 步骤视为未执行 |
| 其他失败（超时、5xx 重试耗尽、JSON 解析失败、非零退出、输出超限） | `ERROR` | `ERROR`（`on_error: empty` 对这些情形不生效） | `SKIPPED` | 步骤视为未执行 |

`foreach` 步骤迭代零次时 `data.<id>` 为 `[]`（不是缺失）。foreach 的来源可以是任意求值为原始数据对象列表的 CEL 表达式（`filter`、`flatten`、列表相加、下标取元素等），引擎求值后按对象引用将结果附加到父元素。构造新对象的表达式（`map` 宏、map 字面量）不能用于 `attach`，否则 lint 拒绝且运行期 `ERROR`。

从属关系：`ctx.folder` 是 `gcloud projects get-ancestors` 返回的直接父 folder id，可能为空（project 直接在 org 下或无法解析）。中间层 folder 和各级独立的 IAM 策略不能用采集步骤"分支"去处理，因为步骤不能按 `ctx.folder` 是否为空来条件执行。若需要 folder 级的 `auditConfigs` 或 sinks，在 organization 级采集后用 `includeChildren`（sinks）或依赖 org 级 IAM 策略（auditConfigs）即可。

模板变量（所有采集器的字符串字段都可用）：

| 变量 | 说明 |
|---|---|
| `.project` | project id |
| `.project_number` | project number |
| `.organization` | organization id（数字），不可解析时为空串 |
| `.folder` | 直接父 folder id，可能为空 |
| `.cluster.name` / `.cluster.location` | `scope: cluster` 时可用；`.cluster` 是完整的 cluster JSON |
| `.params.<name>` | 参数 |
| `.<as>` | foreach 当前元素 |

去重：渲染后完全相同的（采集器, 命令, 作用域）只执行一次，跨规则共享结果。

## 4. 作用域与资源展开

### 4.1 `scope`

- `project`：对每个目标 project 执行；`ctx.project` 可用。
- `organization`：采集在同一 organization 内跨 project 共享。必须设置 `evaluate_per`：值为 `organization` 时每个 organization 只评估一次；值为 `project` 时对 organization 内的每个目标 project 各评估一次（例如 3.8 判断"本 project 是否在某个 perimeter 内"）。`ctx.organization` 为空则 `SKIPPED`。
- `cluster`：引擎先执行 `gcloud container clusters list --project=<p> --format=json`，对每个集群执行；该集群的完整 JSON 注入 `ctx.cluster`，并作为隐式步骤 `data.cluster`。没有集群 → 规则 `NOT_APPLICABLE`。

### 4.2 `resource`

| 字段 | 说明 |
|---|---|
| `from` | CEL，求值为列表，即**被检查的总体**（population）。每个元素作为 `r` 评估一次，产生一条结果。写总体，不要写违规子集 |
| `filter` | CEL bool，可选。只评估为 true 的元素；其余不产生结果 |
| `kind` | 静态字符串，资源类型，用 API 资源名，如 `compute.googleapis.com/Instance`、`k8s.io/Node` |
| `name` | CEL string，可选，默认 `r.name`。报告中的资源名，也是豁免匹配的目标；引擎在名字不以 `projects/`、`organizations/`、`folders/` 开头时自动加 `projects/<id>/`（cluster 作用域再加 `clusters/<name>/`）前缀 |
| `key` | CEL string，可选，默认等于规范化后的 name。`resource.key` 相同的元素合并为一个结果，状态优先级 `FAIL` > `ERROR` > `REVIEW` > `SKIPPED` > `PASS`，证据拼接。由引擎实现（后续里程碑） |
| `empty` | `not_applicable`（默认）\| `pass`。总体为空（或 filter 后为空）时的规则状态。"X 不得存在"类规则用 `pass` |

省略 `resource` 时规则是聚合规则：`r` 不可用，`assert` 直接基于 `data` 判定，结果名为 project / organization / cluster 名。

## 5. 判定（`check`）

评估顺序，对每个资源（或聚合规则一次）：

1. `assert` 求值为 `false` → `FAIL`，消息用 `message`。
2. 否则若存在 `review_when` 且求值为 `true` → `REVIEW`，消息用 `review_message`。
3. 否则 `PASS`。

任一表达式运行时错误 → 该资源 `ERROR`，报告附错误与表达式。

`message` / `review_message` 的渲染是尽力而为：引擎以 `missingkey=zero` 渲染模板，缺失的字段输出为空串；渲染过程中的任何错误（例如中间字段不存在导致的 nil 求值）都不会改变状态，只会在报告里用默认消息并附上渲染错误。模板里只引用稳定存在的字段（`r.name`、`params.*`），细节放到 `evidence`。

### 5.1 CEL 环境

| 变量 | 类型 | 内容 |
|---|---|---|
| `r` | dyn | 当前资源（`resource.from` 的元素，含 foreach 附加的字段） |
| `data` | map(string, dyn) | 所有采集步骤结果，按步骤 id |
| `params` | map(string, dyn) | 合并后的参数 |
| `ctx.project` | string | project id |
| `ctx.project_number` | string | project number |
| `ctx.organization` | string | organization id 或空串 |
| `ctx.organization_domain` | string | organization 的 displayName（通常是主域名）或空串 |
| `ctx.folder` | string | `gcloud projects get-ancestors` 返回的直接父 folder id，可能为空 |
| `ctx.cluster` | dyn | `scope: cluster` 时的集群 JSON，否则 null |
| `ctx.now` | timestamp | 扫描开始时间 |
| `ctx.account` | string | gcloud 当前账号 |

启用的 CEL 扩展：`strings`、`lists`、`sets`、`math`、`encoders`、`bindings`（`cel.bind(x, expr, body)` 用于避免重复子表达式）、optional types、跨数值类型比较。

已知陷阱：`indexOf` 只对字符串可用，列表没有 `indexOf`；需要"有序等级"比较时用 map 参数（如 `severity_rank: {warning: 7, error: 8}`）并写 `params.severity_rank[v] >= params.severity_rank[params.min_level]`。跨数值类型比较：`<`、`<=`、`>`、`>=` 在 int、uint、double 之间可以直接比较（如 `1 < 1.0` 为 false，`2 >= 1u` 为 true）；`==` 在两个不同数值类型的字面量之间不能通过编译（`1 == 1.0` 报 `no matching overload`），但从 `data`、`params`、`r` 取出的 dyn 值在运行时按数值相等（`data.n == 1.0` 中若 data.n 是 int 1，结果为 true）。`data` 与 `params` 是 `map(string, dyn)`，`r` 与 `ctx` 是 dyn，其中的值在运行时按动态类型处理 — 类型错误只会在运行时暴露，因此每条规则都应配 fixture 测试。

JSON 数字：没有小数部分的作为 `int` 暴露，其余为 `double`。

### 5.2 自定义函数（只有这六个）

| 函数 | 语义 |
|---|---|
| `portRangeContains(range string, port int) bool` | `"22"`、`"20-30"`、`""`（空表示全部端口）是否包含 port |
| `modeAtMost(mode string, max string) bool` | 八进制权限位 `mode` 是否不超过 `max`，即 `(mode &^ max) == 0`；`"600"`、`"644"` 对 `"644"` 为 true，`"700"` 为 false |
| `days(n int) duration` | `n` 天的 duration，用于 `ctx.now - timestamp(x) > days(90)` |
| `cidrIsPublic(cidr string) bool` | `0.0.0.0/0`、`::/0`、或前缀长度为 0 的任何写法为 true |
| `cidrIsPrivate(cidr string) bool` | RFC 1918、`100.64.0.0/10`、`169.254.0.0/16`、`fc00::/7`、`fe80::/10`、回环地址范围内为 true；单个 IP 视为 /32 或 /128 |
| `cidrContains(outer string, inner string) bool` | `inner`（CIDR 或单个 IP）是否完全落在 `outer` 内 |

资源命名约定：Compute 资源在 region/zone 间可能重名，`resource.name` 用 selfLink 的路径部分（如 `regions/us-central1/subnetworks/default`、`zones/us-central1-a/instances/web-1`）：`r.selfLink.substring(r.selfLink.indexOf("/projects/") + 1)` 之后再去掉 `projects/<id>/`，或直接 `r.selfLink.substring(r.selfLink.indexOf("/regions/") + 1)` 一类写法。

### Shared VPC

项目在 Shared VPC 场景下可能持有服务 project 的身份：网络、子网、防火墙规则在宿主 project 中，实例与服务在服务 project 中。处理方式：

- 采集同一资源时自动跨 project：gcloud 步骤用 `{{ .project }}`（对服务 project）；REST 步骤引用资源路径中的宿主 project id（例如集群的 `networkConfig.network` 是 `projects/<host>/global/networks/<net>`，子网描述时用 `<host>` 作为 project 参数）。
- 规则是否适用于服务 project 由 `services` 声明决定：如果 `compute.googleapis.com` 在声明中而 Compute API 在服务 project 上也已启用，则该规则也适用于服务 project。
- 默认不用 `getEffectiveFirewalls`（它是一个合成了网络层级防火墙规则的服务端计算 API；gcloud 命令无等价项，REST 调用需要 instance 级别的 `networkInterface` 信息）。规则 5.6.6 在 GKE 场景下可通过 `api` 采集器使用该 API，但通用 VM 防火墙规则不依赖它。

### 可选的 kubectl 采集

GKE 规则可能需要在集群内采集（kubectl）和集群外采集（gcloud/api）联合判定。步骤可以只带 `requires: [kubectl]`，`on_error: ignore`：kubectl 不可用时该步骤跳过，规则用剩余的集群级数据继续评估。5.8.2 是典型示例（authenticatorGroupsConfig 来自 gcloud，RBAC 绑定来自 kubectl）。

### 5.3 常用写法

```
r.?disabled.orValue(false)                       # 可能缺失的布尔
r.?sourceRanges.orValue([])                      # 可能缺失的列表
has(r.settings.ipConfiguration)                  # 字段存在性（父对象必须存在）
r.settings.?ipConfiguration.?ipv4Enabled.orValue(true)   # 链式可选
data.items.exists(i, i.name == "default")
data.items.all(i, i.enabled)
r.labels.?env.orValue("") in params.allowed_envs
r.name.matches("^projects/[^/]+/zones/")         # RE2
ctx.now - timestamp(r.validAfterTime) > days(90)
size(r.members.filter(m, m.startsWith("user:"))) > 0
r.email.endsWith("-compute@developer.gserviceaccount.com")
"serviceAccount:" + r.email in b.members
```

注意：`has()` 作用于 map 时要求父路径存在；链式不确定时用 `.?`。字符串比较区分大小写，必要时 `lowerAscii()`。

## 6. 状态

见设计文档 D8。规则作者只需关心：`assert` 决定 FAIL，`review_when` 决定 REVIEW，`resource.empty` 决定空总体的含义，`services` 决定 NOT_APPLICABLE，`requires` 决定 SKIPPED。

## 7. `mode` 的含义与写法

- `deterministic`：默认判定在任何组织都成立。可以有 `params`（如端口列表），但默认值就是安全基线。
- `contextual`：判定依赖组织上下文。要求：
  1. `params` 中有组织应当调整的项（白名单、期望值、命名约定），默认值保守；
  2. 或者有 `review_when`，把"拿不准"的情况交给人工，并在 `review_message` 里说清楚要确认什么；
  3. `notes` 说明为什么需要上下文、调什么参数后可以收敛为确定判定。

CIS 的 `manual` 不等于 `contextual`：`1.14`（API key 限制）在 CIS 是 Manual，但判定可以是 deterministic；`5.2.1`（GKE 节点 SA）在 CIS 是 Automated，但"自定义 SA 是否最小权限"需要上下文。

## 8. 严重级别映射

| 级别 | 适用 |
|---|---|
| `critical` | 数据或管理面对匿名/全体认证用户公开；管理员凭据失控 |
| `high` | 特权、凭据、网络暴露、加密缺失导致的直接入侵路径 |
| `medium` | 日志、监控、告警、加固项缺失，影响检测与响应 |
| `low` | 纵深防御、L2 的保守项、组织治理约定 |
| `info` | 仅提供信息 |

## 9. 示例

### 9.1 资源级 + 自定义函数（GCP 3.6）

```yaml
- id: cis-gcp-3.6
  ref: "3.6"
  title: Ensure That SSH Access Is Restricted From the Internet
  profile: L2
  cis_assessment: automated
  mode: deterministic
  severity: high
  scope: project
  services: [compute.googleapis.com]
  collect:
    - id: firewalls
      gcloud: compute firewall-rules list --project={{ .project }} --format=json
  resource:
    from: data.firewalls
    kind: compute.googleapis.com/Firewall
    name: r.name
    empty: pass
  params:
    ports: [22]
    public_ranges: ["0.0.0.0/0", "::/0"]
  check:
    assert: |
      !(
        r.direction == "INGRESS"
        && !r.?disabled.orValue(false)
        && r.?sourceRanges.orValue([]).exists(s, s in params.public_ranges)
        && r.?allowed.orValue([]).exists(a,
             a.IPProtocol in ["tcp", "all"]
             && (!has(a.ports) || a.ports.exists(p, params.ports.exists(port, portRangeContains(p, port)))))
      )
    message: "Firewall rule {{ .r.name }} allows TCP port(s) {{ .params.ports }} from {{ .r.sourceRanges }}"
  evidence: [r.sourceRanges, r.allowed, r.targetTags, r.network]
  remediation: |
    gcloud compute firewall-rules update <RULE> --source-ranges=<TRUSTED_CIDRS>
    or delete the rule: gcloud compute firewall-rules delete <RULE>
  references:
    - https://cloud.google.com/vpc/docs/using-firewalls
  notes: |
    Mirrors the CIS audit: INGRESS + 0.0.0.0/0 + tcp/all + port 22 (or no port restriction).
    Disabled rules are ignored. ::/0 is added to the default public ranges.
    Rules that allow the port only to specific target tags still fail, as in CIS.
```

### 9.2 foreach（GCP 1.5）

```yaml
- id: cis-gcp-1.5
  ref: "1.5"
  title: Ensure That There Are Only GCP-Managed Service Account Keys for Each Service Account
  profile: L1
  cis_assessment: automated
  mode: deterministic
  severity: high
  scope: project
  services: [iam.googleapis.com]
  collect:
    - id: service_accounts
      gcloud: iam service-accounts list --project={{ .project }} --format=json
    - id: user_keys
      foreach: data.service_accounts
      as: sa
      attach: user_keys
      gcloud: iam service-accounts keys list --iam-account={{ .sa.email }} --managed-by=user --format=json
  resource:
    from: data.service_accounts
    kind: iam.googleapis.com/ServiceAccount
    name: r.email
  check:
    assert: size(r.?user_keys.orValue([])) == 0
    message: "Service account {{ .r.email }} has user-managed key(s)"
  evidence: ["r.user_keys.map(k, k.name)"]
  remediation: gcloud iam service-accounts keys delete <KEY_ID> --iam-account=<SA_EMAIL>
  references:
    - https://cloud.google.com/iam/docs/best-practices-for-managing-service-account-keys
  notes: |
    Google-managed keys are excluded by --managed-by=user. Default service accounts
    (compute, App Engine) are included because they can also carry user-managed keys.
```

### 9.3 聚合规则 + 采集 + 判定（GCP 2.5）

```yaml
- id: cis-gcp-2.5
  ref: "2.5"
  title: Ensure Log Metric Filter and Alerts Exist for Project Ownership Assignments/Changes
  profile: L1
  cis_assessment: automated
  mode: deterministic
  severity: medium
  scope: project
  collect:
    - id: metrics
      gcloud: logging metrics list --project={{ .project }} --format=json
      on_error: empty
    - id: alert_policies
      gcloud: monitoring policies list --project={{ .project }} --format=json
      on_error: empty
  params:
    filter_patterns:
      - 'cloudresourcemanager\.googleapis\.com'
      - 'ProjectOwnership|projectOwnerInvitee'
      - 'roles/owner'
    require_notification_channel: true
  check:
    assert: |
      data.metrics.exists(m,
        params.filter_patterns.all(p, m.?filter.orValue("").matches(p))
        && data.alert_policies.exists(ap,
             ap.?enabled.orValue(false)
             && (!params.require_notification_channel || size(ap.?notificationChannels.orValue([])) > 0)
             && ap.?conditions.orValue([]).exists(c,
                  c.?conditionThreshold.?filter.orValue("").contains("logging.googleapis.com/user/" + m.name))))
    message: "No enabled alert policy backed by a log metric for project ownership changes"
  evidence: ["data.metrics.map(m, m.name)", "data.alert_policies.map(p, p.displayName)"]
  remediation: |
    gcloud logging metrics create <NAME> --description="Owner changes" --log-filter='<FILTER>'
    then create an alert policy on logging.googleapis.com/user/<NAME> with a notification channel
  references:
    - https://cloud.google.com/logging/docs/logs-based-metrics/
    - https://cloud.google.com/monitoring/alerts
  notes: |
    Alert policies are collected with the GA gcloud monitoring policies list command. Its JSON
    resources expose the Monitoring API alert-policy fields consumed by the assertion.
    Filter matching is pattern-based rather than exact-string to tolerate whitespace and quoting
    differences. A notification channel is required by default; set
    require_notification_channel=false to relax.
```

### 9.4 `on_error: empty`（GCP 2.16）

```yaml
- id: cis-gcp-2.16
  ref: "2.16"
  title: Ensure 'Access Approval' is 'Enabled'
  profile: L2
  cis_assessment: manual
  mode: deterministic
  severity: medium
  scope: project
  collect:
    - id: settings
      gcloud: access-approval settings get --project={{ .project }} --format=json
      on_error: empty
  check:
    assert: |
      size(data.settings.?enrolledServices.orValue([])) > 0
      && size(data.settings.?notificationEmails.orValue([])) > 0
    message: "Access Approval is not enrolled or has no notification emails"
  evidence: [data.settings]
  remediation: gcloud access-approval settings update --project=<PROJECT> --enrolled_services=all --notification_emails=<EMAILS>
  references:
    - https://cloud.google.com/assured-workloads/access-approval/docs/overview
  notes: |
    CIS marks this Manual because the API returns errors when the product is not enrolled.
    The API-not-enabled and FAILED_PRECONDITION errors both mean "not enabled", so on_error: empty
    turns them into an empty settings object and the assertion fails. Permission errors still SKIP.
    accessapproval.googleapis.com is deliberately not listed in services.
```

### 9.5 `filter` 与默认值（GCP 6.3.1）

```yaml
- id: cis-gcp-6.3.1
  ref: "6.3.1"
  title: Ensure 'external scripts enabled' Database Flag for Cloud SQL SQL Server Instance Is Set to 'off'
  profile: L1
  cis_assessment: automated
  mode: deterministic
  severity: medium
  scope: project
  services: [sqladmin.googleapis.com]
  collect:
    - id: sql_instances
      gcloud: sql instances list --project={{ .project }} --format=json
  resource:
    from: data.sql_instances
    filter: r.?databaseVersion.orValue("").startsWith("SQLSERVER")
    kind: sqladmin.googleapis.com/Instance
    name: r.name
  params:
    flag: external scripts enabled
    expected: "off"
  check:
    assert: |
      !r.settings.?databaseFlags.orValue([]).exists(f, f.name == params.flag && f.value != params.expected)
    message: "Instance {{ .r.name }} sets '{{ .params.flag }}' to a value other than {{ .params.expected }}"
  evidence: [r.settings.databaseFlags]
  remediation: gcloud sql instances patch <INSTANCE> --database-flags="external scripts enabled"=off
  references:
    - https://cloud.google.com/sql/docs/sqlserver/flags
  notes: |
    The CIS default value for this flag is off, so an absent flag is compliant; only an explicit
    non-off value fails. Flags whose default is non-compliant must require explicit presence instead.
```

### 9.6 `scope: cluster` + `review_when`（GKE 5.2.1）

```yaml
- id: cis-gke-5.2.1
  ref: "5.2.1"
  title: Use custom least privilege service accounts for GKE node pools
  profile: L1
  cis_assessment: automated
  mode: contextual
  severity: high
  scope: cluster
  services: [container.googleapis.com]
  collect:
    - id: iam_policy
      gcloud: projects get-iam-policy {{ .project }} --format=json
  resource:
    from: ctx.cluster.?nodePools.orValue([])
    filter: "!ctx.cluster.?autopilot.?enabled.orValue(false)"
    kind: container.googleapis.com/NodePool
    name: ctx.cluster.name + "/" + r.name
  params:
    broad_roles: [roles/owner, roles/editor]
    approved_node_roles:
      - roles/container.defaultNodeServiceAccount
      - roles/artifactregistry.reader
      - roles/logging.logWriter
      - roles/monitoring.metricWriter
      - roles/monitoring.viewer
      - roles/stackdriver.resourceMetadata.writer
      - roles/autoscaling.metricsWriter
  check:
    assert: |
      r.config.?serviceAccount.orValue("default") != "default"
      && !r.config.serviceAccount.endsWith("-compute@developer.gserviceaccount.com")
      && !data.iam_policy.?bindings.orValue([]).exists(b,
           b.role in params.broad_roles
           && ("serviceAccount:" + r.config.serviceAccount) in b.?members.orValue([]))
    review_when: |
      data.iam_policy.?bindings.orValue([]).exists(b,
        !(b.role in params.approved_node_roles)
        && ("serviceAccount:" + r.config.serviceAccount) in b.?members.orValue([]))
    message: "Node pool {{ .r.name }} uses the Compute Engine default service account or a service account with a broad role"
    review_message: "Node pool {{ .r.name }} uses {{ .r.config.serviceAccount }}, which holds roles outside approved_node_roles; confirm least privilege"
  evidence: [r.config.serviceAccount, r.config.oauthScopes]
  remediation: |
    gcloud container node-pools create <POOL> --cluster=<CLUSTER> --location=<LOCATION> --service-account=<CUSTOM_SA>
    then migrate workloads and delete the old pool.
  references:
    - https://cloud.google.com/kubernetes-engine/docs/how-to/hardening-your-cluster#use_least_privilege_sa
  notes: |
    Node pools come from ctx.cluster.nodePools, so no extra collection is needed. Autopilot clusters
    are filtered out (Google manages the node service account). "Least privilege" of a custom SA needs
    organization context: broad roles fail outright, roles outside approved_node_roles produce REVIEW.
```

### 9.7 kubectl（GKE 4.1.6）

```yaml
- id: cis-gke-4.1.6
  ref: "4.1.6"
  title: Avoid granting cluster admin level access through the system:masters group
  profile: L1
  cis_assessment: automated
  mode: deterministic
  severity: high
  scope: cluster
  requires: [kubectl]
  collect:
    - id: crb
      kubectl: get clusterrolebindings -o json
    - id: rb
      kubectl: get rolebindings --all-namespaces -o json
  resource:
    from: data.crb.items + data.rb.items
    kind: rbac.authorization.k8s.io/Binding
    name: r.?metadata.?namespace.orValue("cluster") + "/" + r.metadata.name
  params:
    allowed_bindings: ["cluster-admin"]
  check:
    assert: |
      !r.?subjects.orValue([]).exists(s, s.kind == "Group" && s.name == "system:masters")
      || r.metadata.name in params.allowed_bindings
    message: "Binding {{ .r.metadata.name }} grants {{ .r.roleRef.kind }}/{{ .r.roleRef.name }} to group system:masters"
  evidence: [r.subjects, r.roleRef]
  remediation: kubectl delete clusterrolebinding <NAME>  (keep the default cluster-admin binding)
  references:
    - https://kubernetes.io/docs/reference/access-authn-authz/rbac/
  notes: |
    Covers the observable part of the CIS audit: bindings referencing system:masters other than the
    default cluster-admin binding. Whether any client certificate or identity mapping places users in
    system:masters is not observable through the API; GKE legacy client certificates are covered by 5.8.1.
```

### 9.8 降级判定 + kubectl（GKE 3.1.1）

```yaml
- id: cis-gke-3.1.1
  ref: "3.1.1"
  title: Ensure that the kubeconfig file permissions are set to 644 or more restrictive
  profile: L1
  cis_assessment: automated
  mode: contextual
  severity: medium
  scope: cluster
  requires: [kubectl]
  collect:
    - id: nodes
      kubectl: get nodes -o json
  resource:
    from: data.nodes.items
    filter: "!ctx.cluster.?autopilot.?enabled.orValue(false)"
    kind: k8s.io/Node
    name: r.metadata.name
  params:
    managed_os_prefix: Container-Optimized OS
  check:
    assert: "true"
    review_when: "!r.?status.?nodeInfo.?osImage.orValue('').startsWith(params.managed_os_prefix)"
    message: "kubeconfig on node {{ .r.metadata.name }} cannot be verified without node access"
    review_message: "node {{ .r.metadata.name }} does not run Container-Optimized OS; kubeconfig file permissions cannot be verified without node access and must be checked manually"
  evidence: [r.status.nodeInfo.osImage]
  remediation: chmod 644 /var/lib/kubelet/kubeconfig on the node (GKE-managed images already enforce this)
  references:
    - https://cloud.google.com/kubernetes-engine/docs/concepts/node-images
  notes: |
    Performs a degraded check without node access: nodes running Container-Optimized OS pass because
    Google manages the kubeconfig file permissions. Non-COS nodes produce REVIEW because the file
    mode cannot be verified without node access. Autopilot clusters are filtered out because they
    have no node access.
```

## 10. 规则 id 稳定性

规则 id 一经发布不得复用或改变含义。基线升级时，若一条建议的内容有实质变化，应用新 id 发布新规则，并在目录中记录替代关系。同一个 id 的 `ref`、`title`、判定逻辑可以调整以修正缺陷或改进准确度，但含义不得改变。这个约束保证由 `finding_key` 标识的历史发现项保持可比性，消费方可以跨扫描对比同一个 id 的结果。

## 11. `verification` 的计算方式

`verification` 是每条规则的验证级别，由 lint 与 fixture 元数据自动计算，规则作者不手填。取值：

- `none`：仅通过 lint 检查（规则引用的字段路径未经 API schema 对照校验）。
- `static`：规则中引用的字段路径已对照 API schema 校验通过，适用于含 REST 或 kubectl 步骤的规则。
- `fixture`：有 pass 与 fail fixture，且每个 gcloud 步骤的数据来源是真实采集的快照（`captured` 或 `captured+mutated`），REST 与 kubectl 步骤的数据可以来自 API schema。gcloud 步骤没有 fixture 时不能达到 `fixture`，因为 gcloud 的输出形状与 REST 资源不完全一致。
- `live`：经人工核对的真实运行或快照。

计算起点为 `none`，满足更高级别的条件后升级。报告中的 `verification` 字段使消费方了解每条规则的置信度。

## 12. 编写检查清单（规则作者与自动化代理都必须逐项核对）

1. 先读基线原文：Profile Applicability、Audit（含 CLI 命令）、Default Value、Additional Information。
2. `id`、`ref`、`title`、`profile`、`cis_assessment` 与基线一致。
3. `scope`：默认 `project`；Audit 在 organization 级执行的用 `organization`；GKE 集群与集群内对象用 `cluster`。
4. `services`：写采集命令依赖的 API；"API 未启用即不合规"的规则不要写。
5. `collect`：优先 GA 的 gcloud 子命令并以 `--format=json` 结尾，总是带 `--project={{ .project }}`（有 `--project` 参数的子命令）；alpha/beta 或无子命令的用 `api`；绝不留 `<PLACEHOLDER>`；只有 list 输出缺字段时才用 foreach + describe。
6. `resource.from` 写总体，`filter` 写适用性，`assert` 写"没有违规"，`empty: pass` 只用于"X 不得存在"类规则。
7. 字段名用 REST 资源 JSON 的 camelCase 名；所有可能缺失的字段用 `.?x.orValue()`。
8. 读 Default Value：默认合规则缺省视为 PASS；默认不合规则要求显式存在。
9. `mode: contextual` 必须满足第 7 节的三个要求。
10. `severity` 按第 8 节映射。
11. `remediation` 取基线 Remediation 的 CLI 命令；`references` 取基线 References 的 1–3 个 URL。
12. `notes` 写清自动化策略、替代了基线哪一步人工判断、已知局限。
13. 只读动词；kubectl 只用 `get`；不写任何会创建、修改、删除资源的命令。
14. YAML：`ref` 加引号；以 `!` 开头的 CEL 表达式必须加引号或用 `|` 块；不用 tab。
