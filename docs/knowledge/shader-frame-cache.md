# Shader Frame Cache

## 概述

Shader Frame Cache 为 NG Shader 效果链提供帧级缓存复用能力。当 shader 参数不变时跳过重复渲染，直接绘制上一帧的缓存图像；参数变化时自动失效并重新渲染。支持按效果链整体缓存（CONTAINER）和按单个效果独立缓存（PER_EFFECT）两种粒度，以及内容命中（ON_PARAM_SAME）和固定间隔跳帧（FIXED_INTERVAL）两种策略。

## 架构

```
Client (RSNode)
  │  RSNGShaderBase::EnableCache(level, skipPolicy)
  │  RSNGShaderBase::Append() — 构建 effect chain
  │  GetRenderEffect() — OnCopyCachePolicyTo 复制策略到 server 副本
  │
  ▼  IPC (Parcel Marshalling/Unmarshalling)
  │
Server (RSNGRenderShaderBase)
  │  Unmarshalling — 重建链 + 读 trailer 恢复 cache policy
  │
  ▼  RSShaderDrawable::OnSync
  │
  │  AppendToGEContainer — 构建 GEVisualEffectContainer
  │  ApplyCacheConfigToGEContainer — 设置 GE cache policy
  │
  ▼  RSShaderDrawable::OnDraw
  │
GE (GEShaderCache::DrawWithCache)
  │  CalcCanvasHash — canvas matrix + bounds + colorType + colorSpace
  │  GEVisualEffectImpl::Hash — filterType + params + canvasInfo
  │  GEIsCacheHit — 比较 paramHash + canvasHash，跳帧计数
  │  hit  → DrawCachedImage（直接画缓存图）
  │  miss → offscreen 渲染 → UpdateContainerCache/UpdateEffectCache
```

## 数据结构

### RS 侧（render_service_base）

| 文件 | 类型 | 职责 |
|------|------|------|
| `rs_frame_cache_level.h` | `RSFrameCacheLevel` | 缓存粒度枚举：NONE / PER_EFFECT / CONTAINER |
| | `RSFrameSkipMode` | 跳帧模式：NONE / ON_PARAM_SAME / FIXED_INTERVAL |
| | `RSFrameSkipPolicy` | 跳帧策略：mode + skipInterval |
| `rs_render_effect_template.h` | `MarshalEffects` | 递归序列化 type+props（不含 end marker） |
| | `Marshalling` | 调 MarshalEffects，然后写 end marker + trailer |
| | `GetTrailerFlags` / `OnMarshalTrailerData` / `OnUnmarshalTrailerData` | per-effect trailer 虚函数 |
| | `MarshalTrailers` / `UnmarshalTrailers` | trailer 序列化/反序列化（head 单次遍历） |
| `rs_render_shader_base.h` | `RSNGRenderShaderBase` | override trailer 虚函数，委托到 cache policy |
| | `ApplyCacheConfigToGEContainer` | 将 RS cache policy 映射到 GE 类型并设置到 container |
| `rs_ui_shader_base.h` | `RSNGShaderBase::EnableCache` | client 侧设置 cacheLevel_ + skipPolicy_，沿链复制 |
| | `OnCopyCachePolicyTo` | client→server 策略复制 |

### GE 侧（graphics_effect）

| 文件 | 类型 | 职责 |
|------|------|------|
| `ge_frame_cache.h` | `GEFrameCacheLevel` | GE 侧缓存粒度枚举（与 RS 侧一一映射） |
| | `GEFrameSkipPolicy` | GE 侧跳帧策略 |
| | `GEFrameCacheData` | 缓存条目：paramHash + canvasHash + cachedImage + remainingSkipFrames |
| | `GEFrameCacheStore` | 缓存存储：container cache + per-effect cache map + skip policies |
| `ge_shader_cache.cpp` | `GEShaderCache::DrawWithCache` | 入口：按 level 分发 |
| | `DrawPerEffect` | 逐效果缓存命中/未命中处理 |
| | `DrawContainer` | 整链缓存命中/未命中处理 |
| | `CalcCanvasHash` | canvas 状态 hash（含 matrix） |
| | `ComputeContainerHash` | 整链 paramHash 合并 |
| | `GEIsCacheHit` | 命中判定：hash 匹配 or 跳帧余额 |

## 序列化格式

```
无 trailer:
  [type1][props1]...[typeN][propsN][END_OF_CHAIN(-1)]

有 trailer:
  [type1][props1]...[typeN][propsN][END_OF_EFFECTS(-2)]
  [num_effects:u32]
  [flags:u32][trailer_data]...   每个 effect，head→tail 顺序
  [END_OF_CHAIN(-1)]
```

- `END_OF_CHAIN(-1)`：parcel 终止符，所有格式都在最后
- `END_OF_EFFECTS(-2)`：effects 列表结束，trailer 段开始
- `flags`：bit mask，bit0 = CACHE_POLICY，未来扩展新增 bit
- `trailer_data`：按 flags 中 set 的 bit 顺序写入对应数据

CACHE_POLICY trailer_data 内容：`[cacheLevel:i32][skipMode:i32][skipInterval:u32]`（12 字节/effect）

### 兼容性

- 旧 client → 新 server：旧 client 写 `END_OF_CHAIN(-1)`，新 server 直接返回，cache policy 默认 NONE
- 新 client（未启用 cache）→ 旧 server：`GetTrailerFlags()` 返回 0，写 `END_OF_CHAIN(-1)`，与基线一致
- 新 client（启用 cache）→ 旧 server：写 `END_OF_EFFECTS(-2)`，旧 server 不认识，shader 链反序列化失败（预期行为，需版本对齐）

### 扩展

新增 trailer 类型（如 content hash）：
1. 定义 `TRAILER_FLAG_xxx = 1 << N`
2. override `GetTrailerFlags` 返回包含新 bit 的 mask
3. override `OnMarshalTrailerData` / `OnUnmarshalTrailerData` 处理新 bit
4. 不需要改 `Marshalling` / `MarshalTrailers` / `UnmarshalTrailers`

## 缓存命中逻辑

```
GEIsCacheHit(cache, paramHash, canvasHash, skipPolicy):
  if !cache.valid → miss
  if cache.paramHash == paramHash && cache.canvasHash == canvasHash → hit (内容命中)
  if skipPolicy.mode == FIXED_INTERVAL && cache.remainingSkipFrames > 0 → hit (跳帧命中)
      remainingSkipFrames--
  else → miss
```

- `paramHash`：filterType + params 内容 hash + canvasInfo（matrix/geo/materialDst）
- `canvasHash`：bounds(width/height/left/top) + colorType + colorSpace + canvas matrix
- ON_PARAM_SAME：仅靠 paramHash + canvasHash 匹配命中
- FIXED_INTERVAL：参数变化时仍按 skipInterval 跳帧，到期后重新渲染

## 关键设计决策

### MarshalEffects 抽取

原递归 `Marshalling` 在 tail 级写 end marker + trailer，但 tail 只能看到自己（nextEffect_ 为 null），无法覆盖整条链的 trailer。将递归逻辑抽取为 `MarshalEffects`（不写 end marker），`Marshalling` 调用后在 head 级写 end marker + trailer，head 有完整链视图。

### Per-effect trailer 格式

trailer 数据按 per-effect 组织（`[flags][data]` per effect），而非 per-section（`[section_type][section_data]`）。单次遍历覆盖所有 trailer 类型，扩展时只需新增 flag bit，不新增遍历。

### ApplyCacheConfigToGEContainer NONE 处理

当 shader 槽位从 CONTAINER 替换为 NONE 时，drawable 复用旧 container 的 cacheStore。NONE 时显式调 `ApplyCachePolicy(NONE, {})` 清除旧缓存，避免下一帧沿用旧 cache level。

### TrimEffectCaches

`UpdateCacheDataFrom` 从旧 container 复制 cacheStore 后，按当前 filter 列表裁剪 per-effect 缓存条目。移出链条的 effect 的 cachedImage 不再被强引用，避免内存泄漏。

## 系统属性

| 属性 | 默认值 | 作用 |
|------|--------|------|
| `persist.sys.graphic.shaderFrameCacheEnabled` | 1（开启） | 总开关 |
| `persist.sys.graphic.shaderCacheDebugOverlay` | 0（关闭） | 调试遮罩：hit 绿色 / miss 红色半透明矩形 |

每个属性持有独立的 `static CachedHandle`，避免共用句柄导致读取错误值。

## Demo

`render_service_client_shader_cache_demo.cpp` 提供 10 个测试用例：

| Case | 模式 | 动画 | 验证点 |
|------|------|------|--------|
| 1 | CONTAINER + ON_PARAM_SAME | shader A↔B | 参数变 miss，稳定 hit |
| 2 | PER_EFFECT + ON_PARAM_SAME | shader A↔B | 同上，per-effect trace |
| 3 | CONTAINER + ON_PARAM_SAME | chain A↔B | 链变化 container miss |
| 4 | PER_EFFECT + ON_PARAM_SAME | chain A↔B | per-effect 独立 hit/miss |
| 5 | NONE | shader A↔B | 无缓存，每帧 draw |
| 6 | PER_EFFECT + ON_PARAM_SAME | chain A固定/B变化 | A hit, B miss |
| 7 | CONTAINER + ON_PARAM_SAME | bg color动画, shader固定 | bg变化不影响 shader cache |
| 8 | CONTAINER + FIXED_INTERVAL(3) | shader固定, 位置动画 | canvasHash变, 跳帧计数 |
| 9 | CONTAINER + FIXED_INTERVAL(3) | shader A↔B | 参数变仍按间隔跳帧 |
| 10 | CONTAINER + FIXED_INTERVAL(3) | 无动画 | 参数稳定, condHash命中 |

## 已知限制与后续规划

- **跳帧计数基于 draw call**：GE 侧 `remainingSkipFrames` 在 `GEIsCacheHit` 中递减，仅在节点被绘制时触发。无脏区不绘制时计数不递减。后续考虑在 RS 侧标脏 + RequestNextVsync 确保跳帧期间节点持续被画。
- **Hash 适配**：GE 侧 `GEFilterParamsWrapper::Hash` 使用原始内存 hash，对 shared_ptr/vector/optional 类型参数有误命中或漏命中风险。后续考虑复用 RS 侧 `CalculateLocalContentHash`（已正确处理这些类型）传入 GE。
- **离屏合成等价性**：CONTAINER 模式在透明 offscreen surface 上合并多 shader 后回贴，alpha 叠加和混合模式可能与 direct draw 不等价。特定 shader（BLEND_CONTENT 类、越界描边类）需 fallback 到 direct draw。
