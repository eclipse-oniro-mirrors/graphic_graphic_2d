# HDR

## 适用范围

改动涉及以下场景时，先读本文，再回到代码确认当前实现：

- HDR 显示与 HDR 投屏（SDR→HDR 颜色空间转换）
- 像素格式协商（FP16/RGBA1010102/RGBA1010108）
- SDR 亮度映射与 EDR（Extended Dynamic Range）
- HDR 元数据（Static/Dynamic Metadata）读写与传递
- AI HDR 增强（GTM/GainMap/AI2020）
- HDR 截图与色彩空间转换
- 色温补偿与线性矩阵计算

本文是背景知识和排查路线，不替代代码。修改前仍需读取对应头文件、实现文件和测试。

## 快速代码地图

| 方向 | 主要文件 |
| --- | --- |
| HDR 工具类 | `rosen/modules/render_service/core/feature/hdr/rs_hdr_util.h`, `rosen/modules/render_service/core/feature/hdr/rs_hdr_util.cpp` |
| 合成侧 HDR 工具 | `rosen/modules/render_service/composer/composer_service/external_depend/hdr/rs_base_hdr_util.h`, `rosen/modules/render_service/composer/composer_service/external_depend/hdr/rs_base_hdr_util.cpp` |
| 亮度控制 | `rosen/modules/render_service_base/include/display_engine/rs_luminance_control.h`, `rosen/modules/render_service_base/src/display_engine/rs_luminance_control.cpp` |
| 元数据辅助 | `rosen/modules/render_service/composer/composer_service/external_depend/metadata_helper.h` |
| 色温补偿 | `rosen/modules/render_service/include/display_engine/rs_color_temperature.h` |
| 颜色空间转换 | `rosen/modules/render_service/render/rs_colorspace_convert.h`, `rosen/modules/render_service/render/rs_colorspace_convert.cpp` |
| HDR 效果亮度 | `rosen/modules/render_service/render/rs_effect_luminance_manager.h` |
| VPE AI HDR 增强 | `plugins/common/libs/vpe/aihdr_enhancer.h`（依赖 `USE_VIDEO_PROCESSING_ENGINE`） |
| 单测 | `rosen/test/render_service/render_service/unittest/feature/hdr/rs_hdr_util_test.cpp` |

## 核心模型

`RSHdrUtil` 是 HDR 功能的核心工具类，提供静态方法处理 HDR 相关逻辑。HDR 管线涉及 SurfaceNode、ScreenNode 和 Buffer 的多层协调。

### HdrStatus 枚举

`HdrStatus` 定义在 `rs_luminance_control.h`，使用位掩码设计支持多种 HDR 类型叠加：

- `NO_HDR = 0x0000`：非 HDR
- `HDR_PHOTO = 0x0001`：HDR 照片
- `HDR_VIDEO = 0x0010`：HDR 视频
- `AI_HDR_VIDEO_GTM = 0x0100`：AI HDR GTM
- `HDR_EFFECT = 0x1000`：HDR 效果
- `AI_HDR_VIDEO_GAINMAP = 0x10000`：AI HDR GainMap
- `HDR_UICOMPONENT = 0x100000`：HDR UI 组件
- `HDR_COLOR = 0x1000000`：HDR 色彩
- `AI_HDR_VIDEO_AI2020 = 0x10000000`：AI HDR AI2020

### HDRType 枚举

- `DEFAULT = 0`：默认类型
- `AIHDR = 1`：AI HDR 类型

### 主要功能模块

**1. HDR Surface 判断**

- `CheckIsHdrSurface`：检查 SurfaceNode 是否为 HDR 内容
- `CheckHasSurfaceWithAiHdrMetadata`：检查是否包含 AI HDR 元数据
- `CheckIsSurfaceWithMetadata`：检查是否包含 HDR 元数据

**2. 亮度映射与 EDR**

- `UpdateSurfaceNodeNit`：更新 SurfaceNode 的 nit 值（亮度）
- `UpdateSelfDrawingNodesNit`：更新自绘制节点的 nit 值
- `SetHDRParam`：设置 HDR 参数
- `CalScaler`：计算亮度缩放因子

关键常量：
- `DEFAULT_HDR_RATIO = 1.0f`：默认 HDR 亮度比
- `DEFAULT_SCALER = 1000.0f / 203.0f`：默认缩放因子
- `GAMMA2_2 = 2.2f`：Gamma 2.2 校正

**3. 像素格式协商**

- `UpdatePixelFormatAfterHwcCalc`：HWC 计算后更新像素格式
- `CheckPixelFormatWithSelfDrawingNode`：检查自绘制节点像素格式
- `CheckPixelFormatForHdrEffect`：检查 HDR 效果像素格式
- `BufferFormatNeedUpdate`：判断 buffer 格式是否需要更新

支持格式：
- FP16（RGBA_F16）：HDR 内容高精度格式
- RGBA1010102：10bit HDR 格式
- RGBA1010108：受 `GetRGBA1010108Enabled()` 控制

**4. 线性矩阵与色温**

- `UpdateSurfaceNodeLayerLinearMatrix`：更新 Layer 线性矩阵（色温补偿）
- 色温补偿通过 `RSColorTemperature` 处理
- 支持多种颜色空间矩阵（BT601/BT709/BT2020/P3）

**5. HDR 投屏**

HDR 投屏涉及 SDR→HDR 颜色空间转换：

输入颜色空间定义（SRGB → BT2020_HLG）：
- 输入：SRGB primaries + SRGB transfunc + BT601 matrix + Full range
- 输出：BT2020 primaries + HLG transfunc + BT2020 matrix + Full range

相关方法：
- `IsHDRCast`：判断是否需要 HDR 投屏
- `UpdateHDRCastProperties`：更新 HDR 投屏属性
- `HDRCastProcess`：HDR 投屏处理
- `SetHDRCastShader`：设置 HDR 投屏着色器
- `HandleVirtualScreenHDRStatus`：处理虚拟屏 HDR 状态

**6. HDR 截图**

- `NeedUseF16Capture`：判断是否需要 FP16 截图
- `HDRColorHeadroomMapping`：HDR 色域头映射

**7. 元数据管理**

- `EraseHDRMetadataKey`：清除 HDR 元数据
- `SetMetadata`：设置 HDR 元数据（两个重载）
- `GetHDRStaticMetadata`：获取静态元数据（maxCLL/maxFALL）
- `GetHDRDynamicMetadata`：获取动态元数据

## 设计背景与决策理由

下面的"代码体现"来自当前实现；"设计意图"包含代码路径、注释、依赖形态和模块责任人补充的背景。

| 决策 | 代码体现 | 设计意图 |
| --- | --- | --- |
| HdrStatus 位掩码设计 | `enum HdrStatus : uint32_t` 各值为 2 的幂次 | 支持多种 HDR 类型叠加判断，通过位运算高效检查 |
| 条件编译 VPE 路径 | `#ifdef USE_VIDEO_PROCESSING_ENGINE` 包裹 HDR 投屏、元数据、AI HDR | VPE（VideoProcessingEngine）是可选模块，条件编译保证跨平台兼容性 |
| FP16 截图判断 | `NeedUseF16Capture` 检查 `HDRPresent` 和 `colorGamut != SRGB` | HDR 内容需要更高精度格式，FP16 保留 HDR 信息；SDR 色域不需要 FP16 |
| 亮度缩放计算 | `CalScaler` 使用 `maxContentLightLevel / 203.0f` | 203 nits 是 SDR 参考亮度，用于计算 HDR→SDR 亮度映射 |
| Gamma 2.2 校正 | `std::pow(layerNits / displayNits, 1.0f / GAMMA2_2)` | 符合人眼感知特性，使亮度变化更自然 |
| 虚拟屏固定 10bit 格式 | `SetFixVirtualBuffer10Bit(true)` 当 `ColorGamut == BT2100_HLG` | HDR 投屏场景下，虚拟屏需要固定 10bit 格式避免格式切换 |
| AI HDR 处理 buffer | `CheckIsHDRSelfProcessingBuffer` 判断后调用 `ProcessEDR` | 部分 HDR buffer 需要硬件/算法增强，区分处理路径 |
| 色温补偿矩阵 | `UpdateSurfaceNodeLayerLinearMatrix` 动态计算 3x3 矩阵 | 不同色域（BT601/BT709/BT2020/P3）需要不同的色温补偿 |
| 元数据擦除 | `EraseHDRMetadataKey` 擦除 STATIC 和 DYNAMIC 元数据 | 避免 HDR 元数据污染 SDR 路径 |
| RGBA1010108 门控 | `GetRGBA1010108Enabled()` 运行时判断 | 部分硬件/驱动不支持 1010108 格式，运行时门控 |

## HDR 投屏处理流程

HDR 投屏（HDRCast）用于将 SDR 内容转换为 HDR 格式投屏显示：

处理流程：
1. HandleVirtualScreenHDRStatus 判断虚拟屏类型（MIRROR_COMPOSITE 镜像模式或 EXPAND_COMPOSITE 扩展模式）
2. 判断条件：源屏 HDR 开启 && 虚拟屏色域 == BT2100_HLG
3. UpdateHDRCastProperties 设置固定 10bit 格式
4. IsHDRCast 返回 true，设置 GRAPHIC_PIXEL_FMT_RGBA_1010102
5. HDRCastProcess 执行颜色空间转换
6. SetHDRCastShader 设置着色器进行 SRGB→BT2020_HLG 转换

关键参数：
- 输入颜色空间：SRGB primaries + SRGB transfunc + BT601 matrix + Full range
- 输出颜色空间：BT2020 primaries + HLG transfunc + BT2020 matrix + Full range
- 元数据类型：CM_VIDEO_HDR_VIVID

## 亮度映射与 EDR

亮度映射是 HDR 的核心功能，将内容亮度映射到显示设备能力范围内：

**UpdateSurfaceNodeNit 流程：**

1. 检查 SurfaceNode 的 `GetVideoHdrStatus()`
2. NO_HDR 时设置 SDR nit 值和默认矩阵
3. HDR 时：
   - 获取静态元数据（`HdrStaticMetadata`）包含 `maxContentLightLevel`
   - 获取动态元数据（如有）
   - 计算 `scaler = CalScaler(maxContentLightLevel, ...)`
   - 应用亮度因子（`GetHDRBrightnessFactor()`）
   - 应用 HDR 调光因子（`HdrDimmingProcess`）
   - 计算 `layerNits = std::clamp(sdrNits * scaler, sdrNits, displayNits)`
   - 计算 `brightnessRatio = std::pow(layerNits / displayNits, 1.0f / GAMMA2_2)`
4. AI HDR 自处理 buffer 调用 `ProcessEDR`

**亮度控制关键方法（RSLuminanceControl）：**

- `GetSdrDisplayNits`：获取 SDR 显示亮度
- `GetDisplayNits`：获取 HDR 显示亮度
- `GetHdrBrightnessRatio`：获取 HDR 亮度比
- `HdrDimmingProcess`：HDR 调光处理
- `CalScaler`：计算亮度缩放因子
- `UpdateMetadataBasedOnScaler`：根据缩放因子更新元数据

## 像素格式协商

像素格式协商根据 HDR 状态和设备能力选择合适格式：

| 格式 | 用途 | 条件 |
| --- | --- | --- |
| RGBA_F16 | HDR 内容高精度 | `NeedUseF16Capture` 返回 true |
| RGBA_1010102 | 10bit HDR | HDR 投屏或硬件 HDR 开启 |
| RGBA_1010108 | 10bit SDR | `GetRGBA1010108Enabled()` 返回 true |
| RGBA_8888 | 标准 SDR | 默认格式 |

**格式更新时机：**
- HWC 计算后：`UpdatePixelFormatAfterHwcCalc`
- 自绘制节点检查：`CheckPixelFormatWithSelfDrawingNode`
- HDR 效果检查：`CheckPixelFormatForHdrEffect`

## 色温补偿

色温补偿通过 3x3 矩阵对不同颜色空间进行校正：

**UpdateSurfaceNodeLayerLinearMatrix 流程：**

1. 从 buffer 获取 `CM_ColorSpaceInfo`（ primaries、transfunc、matrix）
2. 获取动态元数据（如有）
3. 调用 `RSColorTemperature::GetLayerLinearCct` 计算矩阵
4. 设置到 `surfaceNode.SetLayerLinearMatrix`

矩阵结构：`[m00, m01, m02, m10, m11, m12, m20, m21, m22]`

## 元数据管理

HDR 元数据分为静态和动态两种：

**静态元数据（HdrStaticMetadata）：**
- `cta861.maxContentLightLevel`：最大内容亮度
- `cta861.minContentLightLevel`：最小内容亮度
- `cta861.maxFrameAverageLightLevel`：最大帧平均亮度

**动态元数据：**
- 场景特定亮度信息
- 用于更精确的亮度映射

**MetadataHelper 方法：**
- `GetColorSpaceInfo`：获取颜色空间信息
- `SetHDRStaticMetadata`：设置静态元数据
- `SetHDRDynamicMetadata`：设置动态元数据（VIVID 格式）
- `SetColorSpaceInfo`：设置颜色空间信息

**HDR VIVID 元数据格式：**
预定义的 `HDR_VIVID_METADATA` 字节数组，符合 HDR Vivid 标准。

## AI HDR 增强

AI HDR 增强依赖 VPE 模块（`USE_VIDEO_PROCESSING_ENGINE`）：

**增强类型：**
- GTM（Global Tone Mapping）
- GainMap（增益映射）
- AI2020

**处理流程：**
1. `CheckIsHDRSelfProcessingBuffer` 判断是否需要处理
2. 创建 `AihdrEnhancer` 实例
3. 设置参数（`targetScaler`、`tmoNits`、`sdrNits`、`displayNits`）
4. 调用 `ProcessEDR` 执行增强

**颜色映射：**
- `HDRColorHeadroomMapping`：处理颜色色域头映射
- 使用 `ProcessHDRColor` 转换非线性 RGB

## HDR 图片通路

HDR 图片显示涉及主线程收集、渲染线程处理和图片绘制三个阶段：

### 主线程：HDR Status 收集

主线程负责收集 HDR 图片的状态，从客户端传递到服务端：

**客户端到服务端传递：**
- `RSCanvasNode::SetHDRPresent`（客户端）通过 RSCommand/Modifier 传递
- 到达 `RSCanvasRenderNode::SetHDRPresent`（服务端）
- 父节点 instanceRootNode 进行计数

**QuickPrepareSurfaceRenderNode 阶段：**
- 调用 `RSHdrUtil::CheckPixelFormatForHdrEffect` 检查节点属性
- 检查 `node.IsHdrEffectColorGamut()` 或 `node.HDRColorHeadroomEnabled()`
- 设置 `screenNode->SetHasUniRenderHdrSurface(true)`
- 调用 `screenNode->CollectHdrStatus(nodeId, HdrStatus::HDR_EFFECT/HDR_COLOR)`

**QuickPrepareScreenRenderNode 阶段：**
- 调用 `RSHdrUtil::UpdatePixelFormatAfterHwcCalc`
- 调用 `RSUniRenderVisitor::HandlePixelFormat`
- 调用 `RSLuminanceControl::SetHdrStatus(screenId, displayHdrStatus)` 将状态传递给亮度控制
- 调用 `RSLuminanceControl::IsHdrOn(screenId)` 获取 HDR 开启决策
- 决策结果传递给渲染线程

**CheckPixelFormat 检查内容：**
- 检查指纹节点，设置 `RGBA_1010102` 格式
- 检查 `node.GetHDRImagePresent()`，收集 `HDR_PHOTO` 状态
- 检查 `node.GetHDRUIPresent()`，收集 `HDR_UICOMPONENT` 状态
- 对每种状态调用 `RSHdrUtil::SetHDRParam` 设置 HDR 参数

**HandlePixelFormat 决策流程：**
- 获取 ScreenId 和 `hasUniRenderHdrSurface` 状态
- 判断 `isCloseHdr`（强制关闭或硬件禁用）
- 将 HDR 状态设置到 `RSLuminanceControl`
- 获取 `isHdrOn` 决策结果和 `brightnessRatio`
- 设置 `node.SetHDRPresent(isHdrOn)`
- 处理虚拟屏 HDR 状态

### 渲染线程：离屏渲染与像素格式

渲染线程根据 HDR 决策结果选择离屏渲染格式和像素格式：

**绘制调用链：**
- `RSScreenRenderNodeDrawable::OnDraw`
- `RSLogicalDisplayRenderNodeDrawable::OnDraw`
- 判断 `needOffscreen = GetNeedOffscreen() || isHdrOn || isScRGBEnable`
- `RSLogicalDisplayRenderNodeDrawable::PrepareOffscreenRender`
- `RSRenderNodeDrawable::OnDraw`（在离屏 surface 上绘制）
- `FinishOffscreenRender`（离屏内容绘制回主 canvas）

**PrepareOffscreenRender 判断逻辑：**
- 获取 screenParams 和 screenProperty
- 判断是否需要创建 F16 离屏 surface：当前无 offscreen 或格式不匹配时需要创建
- 判断 `hdrOrScRGB = screenParams->GetHDRPresent() || curCanvas_->GetHDREnabledVirtualScreen() || EnablescRGBForP3AndUiFirst(...)`
- 当 `hdrOrScRGB` 为 true 时：
  - 设置 `colorType = COLORTYPE_RGBA_F16`
  - 设置 `colorSpace = CreateSRGB()`
  - 如果硬件禁用或 canvas 可替换，则使用 buffer 格式
  - 创建 offscreen surface

**像素格式选择：**
- 当 `isHdrOn = true` 时，使用 10bit 像素格式
- 部分机型使用 `RGBA_1010108`（受 `GetRGBA1010108Enabled()` 控制）
- 大部分机型使用 `RGBA_1010102`

### 图片绘制：Tone Mapping 与色域转换

图片绘制时需要进行 HDR 到 SDR 的转换：

**绘制调用链：**
- `RSExtendImageObject::Playback`（或 `DrawImageWithParmOpItem::Playback`）
- 获取 PixelMap 和采样参数
- `RSImage::CanvasDrawImage`
- `RSImage::HDRConvert`
- `RSColorSpaceConvert::ColorSpaceConvertor`
- `colorSpaceConverterDisplay_->Process`
- 使用生成的 shader 绘制

**HDRConvert 判断逻辑：**
- 检查 `isHDRPixelMap`（PixelMap 是否为 HDR 格式）
- 检查 `isEDRSurface`（是否为 EDR surface）
- 检查 `isHDRUiCapture`（是否为 HDR UI 截图）
- 任一条件满足时继续处理
- 创建 ImageShader（包含缩放和平移矩阵）
- 获取目标颜色空间
- 判断是否需要 HDR TMO（非多屏、非 SDR 截图、HDR 开启）

**ColorSpaceConvertor 处理：**
- 设置 VPEParameter（包含颜色空间、亮度、动态范围模式等）
- 设置 surface buffer 的颜色空间信息
- 设置目标颜色空间、screenId、dynamicRangeMode
- 调用 `colorSpaceConverterDisplay_->Process`
- VPE（VideoProcessingEngine）进行 Tone Mapping
- 亮度映射（Brightness Mapping）
- 色域转换（Gamut Conversion）
- 生成输出 shader
- 设置到 paint 的 shader effect

**关键判断条件：**
- `isHDRPixelMap`：PixelMap 为 F16 格式且 HDR 色域
- `isEDRSurface`：EDR surface（Extended Dynamic Range）
- `isHDRUiCapture`：DMA + F16 + BT2020 色域的 UI 截图
- `isHDRTmo`：根据截图类型和 HDR 状态判断是否需要 Tone Mapping

**ColorSpaceConvertor 处理内容：**
- 设置 VPE 参数（包含颜色空间、亮度、动态范围模式等）
- 调用 VPE 处理生成输出 shader
- 设置 shader 到 paint

**VPE 处理内容：**
- Tone Mapping：将 HDR 高动态范围映射到 SDR
- Brightness Mapping：根据亮度比调整亮度
- Gamut Conversion：颜色空间转换（如 BT2020 → sRGB/P3）
- 生成 GPU Shader 用于硬件加速渲染

## 虚拟屏 HDR 处理

虚拟屏有两种合成模式需要 HDR 处理：

**MIRROR_COMPOSITE（镜像模式）：**
- 检查镜像源屏的 HDR 状态
- 源屏 HDR 开启且虚拟屏色域为 BT2100_HLG 时启用 HDR 投屏

**EXPAND_COMPOSITE（扩展模式）：**
- 检查当前屏的 HDR 状态
- 当前屏 HDR 开启且虚拟屏色域为 BT2100_HLG 时启用 HDR 投屏

## HDR 截图

HDR 截图需要特殊处理保留 HDR 信息：

**NeedUseF16Capture 判断条件：**
- 主屏使用 F16 buffer（`GetHDRPresent()`）
- 或 scRGB 模式开启（`IsNeedScRGBForP3`）
- 且窗口色域不是 SRGB

**HDRColorHeadroomMapping：**
- 获取当前显示色域头（`displayHeadroom`）
- 计算期望色域头和实际色域头的映射
- 调用 AI HDR 颜色处理

## 规格限制

| 限制项 | 当前值 | 代码锚点 |
| --- | --- | --- |
| SDR 参考亮度 | 203 nits | `DEFAULT_SCALER = 1000.0f / 203.0f` |
| Gamma 校正值 | 2.2 | `GAMMA2_2 = 2.2f` |
| 矩阵大小 | 9 | `MATRIX_SIZE = 9` |
| HDR 投屏 HDR Nits | 1000 nits | `RSLuminanceConst::DEFAULT_CAST_HDR_NITS` |
| HDR 投屏 SDR Nits | 203 nits | `RSLuminanceConst::DEFAULT_CAST_SDR_NITS` |

## 常见故障排查

### HDR 内容显示异常

优先检查：
- SurfaceNode 的 `GetVideoHdrStatus()` 是否正确
- ScreenNode 的 `GetHDRPresent()` 是否设置
- 像素格式是否为 FP16 或 RGBA1010102
- `RSLuminanceControl::IsForceCloseHdr()` 是否强制关闭 HDR
- `IsHardwareHdrDisabled` 是否禁用硬件 HDR

### 亮度映射不正确

优先检查：
- `layerNits`、`displayNits`、`sdrNits` 的值
- `scaler` 计算是否正确
- 静态元数据 `maxContentLightLevel` 是否读取成功
- `brightnessFactor` 和 `hdrDimmingFactor` 是否正确

### HDR 投屏失败

优先检查：
- 虚拟屏色域是否为 BT2100_HLG
- 源屏 HDR 状态是否正确
- `SetFixVirtualBuffer10Bit` 是否设置
- VPE 模块是否可用（`USE_VIDEO_PROCESSING_ENGINE`）
- 着色器是否正确设置

### 像素格式协商错误

优先检查：
- `GetRGBA1010108Enabled()` 返回值
- HWC 是否被禁用（`IsHardwareForcedDisabled`）
- `UpdatePixelFormatAfterHwcCalc` 是否执行
- SDR nit 值是否变化（`isSdrNitsChanged`）

### 色温补偿异常

优先检查：
- buffer 颜色空间信息是否正确（`MetadataHelper::GetColorSpaceInfo`）
- 动态元数据是否读取成功
- 矩阵大小是否为 9（`MATRIX_SIZE`）
- `RSColorTemperature` 是否正确初始化

### 元数据读写失败

优先检查：
- buffer 是否为 nullptr
- 元数据 key 是否正确（`ATTRKEY_HDR_STATIC_METADATA`、`ATTRKEY_HDR_DYNAMIC_METADATA`）
- VPE 模块是否可用（`USE_VIDEO_PROCESSING_ENGINE`）
- 元数据大小是否匹配

## 验证建议

构建命令从 OpenHarmony 源码根目录执行，使用 `./build.sh --product-name <product-name> --build-target graphic_2d --ccache`。

就近单测目标：
- `rs_hdr_util_test`

涉及硬件 HDR、VPE、AI HDR 增强时，需要真实设备验证。没有设备时，应记录缺失的真实设备验证项。

## 改动检查清单

- 是否确认 HdrStatus 位掩码操作正确性？
- 是否检查像素格式协商的完整路径（HWC、自绘制、HDR 效果）？
- 是否确认亮度映射的 scaler 计算和边界处理？
- 是否检查虚拟屏 HDR 投屏的两种模式？
- 是否确认元数据的读写和擦除操作？
- 是否同步色温补偿矩阵的变化？
- 是否检查条件编译（`USE_VIDEO_PROCESSING_ENGINE`）的完整性？
- 是否需要真实设备验证？
- 是否避免在热点路径增加大内存拷贝或高频日志？

## 待补充背景

这些内容需要模块责任人后续补充，不能仅靠静态扫描完全确定：

- 各 HdrStatus 类型的完整判断逻辑和触发场景
- RGBA1010108 格式的硬件支持列表和运行时判断逻辑
- AI HDR 各类型（GTM/GainMap/AI2020）的详细差异和使用场景
- HDR 投屏在不同芯片平台的兼容性问题
- 真实设备 HDR 显示效果验证用例和常用验证命令
- 历史线上问题典型案例
