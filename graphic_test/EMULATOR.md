# graphic_test 模拟器端侧运行指南

本实现面向 OpenHarmony `x86_64_virt` 分部渲染、1200×2000 单模拟器实例。
端侧只负责预检、执行、出图和落盘自检；像素比对、基线管理和视觉报告不在端侧实现。

## 1. 构建目标

从 OpenHarmony 源码根目录构建：

```bash
./build.sh --product-name x86_64_virt --ccache --deps-guard=false \
  --build-target "foundation/graphic/graphic_2d/graphic_test/test:RSGraphicTest" \
  "foundation/graphic/graphic_2d/graphic_test/test:RSGraphicTestFrameworkTest"
```

`RenderServiceRenderProfilerTest` 保持独立，不纳入模拟器视觉产物。

## 2. 只读预检

资源图片由宿主机直接推到 `/data/local/tmp/` 后运行：

```bash
/data/local/tmp/RSGraphicTest -preflight \
  --test-binary /data/local/tmp/RSGraphicTest \
  --expected-width 1200 --expected-height 2000
```

检查项：

- 资源表内 42 个设备路径的文件存在性、普通文件类型和符号链接逃逸；
- 测试二进制大小；
- 产品身份必须为 `x86_64_virt`，渲染模式必须为 divided；
- 实际显示尺寸必须符合预期；
- 输出分区空间是否满足“计划截图数 × 单图上限”（默认 10 MiB，可用 `--max-png-bytes` 调整）；
  输出目录不存在时，只读查询最近一级已存在的父目录。

输出为纯文本：`INFO ...` 环境信息行、`FAIL <code> <message> <path>` 问题行，
最后一行 `PASSED` 或 `FAILED`。退出码 0 表示通过，2 表示基础设施错误。

## 3. 执行套件

```bash
/data/local/tmp/RSGraphicTest -emulator-run \
  --output-root /data/local/graphic_test_emulator \
  --run-id smoke-001 \
  --suite HwcTest \
  --suite-timeout-ms 300000 \
  --display-fallback
```

`--suite` 选择单个套件，`--suites` 接收逗号分隔列表，二者互斥。
省略套件参数时执行全部套件。用例清单来自二进制内注册表，无需传递 catalog 文件。
子进程在任何用例产生记录前退出（排除文件读取失败、初始化崩溃等）时，
剩余用例记为 `INFRA_ERROR`，直接停止，不再重启。

`--flush-settle-ms N`（默认 100）：分离渲染下 flush 回调不触发，等待回调超时是纯耗时。
该参数把子进程的 flush 行为改为"发送命令后固定等待 N 毫秒"，画面完整性由双次截图确认兜底。
传 0 恢复原来的回调等待行为。该值写入执行策略，不同的值续跑时会分配新目录。

续跑：

```bash
/data/local/tmp/RSGraphicTest -emulator-run \
  --output-root /data/local/graphic_test_emulator \
  --run-id smoke-001 --resume --display-fallback
```

续跑核对测试二进制身份（大小+修改时间）、显示配置和执行策略。
身份不匹配时分配 `runId-rN` 新目录，旧目录原样保留。
业务自截图用例（`GRAPHIC_N_TEST`，由用例自行截图写图）默认只列清单，不执行；
显式传 `--include-manual` 才纳入执行，但不计入框架截图用例分母。

## 4. 内部子进程入口

正常调用由 runner 发起，不建议直接用于全量跑测：

```bash
/data/local/tmp/RSGraphicTest -emulator-unit \
  --suite HwcTest \
  --output-dir /data/local/graphic_test_emulator/smoke-001/HwcTest/attempt1 \
  --exclude-cases-file /data/local/graphic_test_emulator/smoke-001/HwcTest/attempt1/exclude_cases.txt \
  --ready-max-retries 3 \
  --display-fallback
```

单例诊断可增加 `--case <CaseName>`。
`-emulator-unit` 与旧 `-unit` 共用 GTest 过滤和 Director 初始化。
排除文件每行一个用例，支持裸用例名或 `Suite.Case`，空行和 `#` 注释忽略。

只有新入口会启用独立输出、回退、双次截图一致性确认和原子落盘。
旧 `-list`、`-unit`、`-all` 不读取这些新配置，默认行为保持不变。

## 5. 产物格式

实际布局：

```text
<output-root>/<runId>/
  run_state.json              # 唯一的 JSON 文件，供 --resume 使用
  <Suite>/
    attempt<N>/
      process.log
      exclude_cases.txt
      <测试目录>/<Suite>_<Case>.png
```

`run_state.json` 包含整轮身份、时间、阶段耗时、执行策略，以及每个用例的最终状态和尝试历史，
采用原子替换写入。宿主机边跑边拉直接取图片目录，退出码判定结果，无需读取任何端侧 JSON。

PNG 先写临时文件，回读文件头确认宽高后改名；不覆盖、不删除旧文件。
出图就绪连续截两次，不一致时按上限重试并记录 `captureUnstable`；达到上限仍保留最后图片，
只有真正截图失败才不落盘。图片清单不含哈希，传输核对由宿主机自行处理。

## 6. 退出状态

| 退出码 | 含义 |
| ---: | --- |
| 0 | 所选范围完成，未出现需要失败的执行或落盘结果 |
| 1 | 用例失败、超时、崩溃、缺图或其它执行失败 |
| 2 | 参数、身份、资源、空间、健康检查或持久化失败 |

失败时仍尽量保存 `run_state.json`（含全部已完成结果）。

## 7. 资源表

资源依赖编在二进制内，见 [资源表](graphic_test/graphic_test_framework/src/rs_graphic_test_resource_table.cpp)。
42 个设备路径和是否必需都是编译期常量；表中 `size` 为 0 表示只检查文件存在且非空，
填入确切大小后会核对实际尺寸。

## 8. 框架单测与验证边界

部署并运行：

```bash
/data/local/tmp/RSGraphicTestFrameworkTest
```

测试覆盖参数、目录、资源表、空间、进程、排除列表、续跑身份、截图配置、PNG 文件头、健康检查。
真实 GN 构建、模拟器代表套件、超时/崩溃恢复、历史 CLI 和真机兼容性必须分别实测，
不能仅由宿主机静态检查替代。健康检查使用 `GetDisplayState()==DisplayState::ON` 作为屏幕可用信号，
真实锁屏场景仍需设备验证。
