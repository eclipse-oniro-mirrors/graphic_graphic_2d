# 模拟器资源表说明

资源依赖编在 [rs_graphic_test_resource_table.cpp](../graphic_test_framework/src/rs_graphic_test_resource_table.cpp)，
端侧不再读取任何资源 JSON 文件。

- `devicePath`：设备上的原始资源路径，保持现有用例契约（`/data/local/tmp/` 前缀）。
- `required`：当前 42 条均为必需；缺失会在 `-preflight` 和 `-emulator-run` 启动时判定失败。
- `size`：为 0 表示只检查文件存在且非空；填入确切字节数后会核对实际大小。

修改资源表后需重新编译 `RSGraphicTest`，资源表随二进制一起部署，宿主机只负责推送图片文件本身。
