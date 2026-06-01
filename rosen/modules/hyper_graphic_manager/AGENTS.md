# HGM (Hyper Graphic Manager) Module Knowledge Base

## OVERVIEW

Hyper Graphic Manager module for OpenHarmony graphics subsystem. Dynamically adjusts display refresh rate (30/60/90/120Hz) via a policy-driven voting framework. Compiles as `libhyper_graphic_manager` shared library.

## STRUCTURE

```
hyper_graphic_manager/
├── core/
│   ├── frame_rate_manager/     # Central orchestrator + sub-managers (HgmFrameRateManager)
│   ├── hgm_screen_manager/     # HgmCore singleton, HgmScreen, HgmScreenInfo
│   ├── config/                 # XML parser, logging macros, IPC callback manager, user defines
│   ├── utils/                  # Shared types, voter primitives, state machine, timers, LRU cache
│   ├── soft_vsync_manager/     # Per-app software VSync rate division
│   └── native_display_soloist/ # Public C API (OH_DisplaySoloist) for app frame rate control
└── frame_rate_vote/            # RSFrameRateVote, RSVideoFrameRateVote (surface buffer voting)
```

## OPERATIONAL FLOW

This section describes how HGM operates within the Render Service (RS). Before proposing any HGM-related changes:
- **Reference this flow** to identify the **optimal approach**
- Changes must be **necessary and correct**
- Do **not** modify existing member variables or functions unless explicitly stated

### Server-Side Initialization

RS initialization starts at `RSRenderService::Init()` (runs once at startup), which calls `RSRenderService::HgmInit()`:

1. **HgmCore initialization**: `HgmCore` is a singleton — first call to `HgmCore::Instance()` triggers the constructor:
   - `InitXmlConfig()` reads HGM XML configuration
   - Creates `hgmFrameRateMgr_` (constructor sets up timers, callbacks)
   - Registers a listener on `persist.sys.mode` system property for refresh-rate mode changes
   - `SetLtpoConfig()` applies XML config values to member variables

2. **HgmContext initialization**:
   - `hgmContext_` is created with required parameters and callbacks
   - `InitHgmTaskHandleThread()` starts `HgmTaskHandleThread`, which posts tasks:
     - `SetForceUpdateCallback` on `frameRateManager`
     - `frameRateManager->Init()` initializes all HGM-related sub-modules
     - `SetHgmConfigUpdateCallback` and `SetAdaptiveVsyncUpdateCallback` on `frameRateManager`
       - These callbacks only transmit data to the render side when values actually change (tracked by `hgmDataChangeTypes_` bit flags), via `SetServiceToProcessInfo`; flags are reset after transmission

Later, during process manager init (`RSRenderService::RenderProcessManagerInit()`), HGM passes the server-side frame-rate decision callback (`HgmContext::ProcessHgmFrameRate()`) to `renderProcessManager_` via `RSRenderProcessManager::Create()`:
- Only in **single-process** mode is the callback wired up; in multi-process mode, frame-rate decision callbacks are not executed
  - Single-process: `RSSingleRenderProcessManager` constructor sets the callback on `RSRenderServiceAgent::hgmProcessCallback_`
  - Each frame's IPC from render side (`NotifyRpHgmFrameRate()`) ultimately invokes this server-side callback

### Render-Side Initialization

During process manager init (`RSRenderService::RenderProcessManagerInit()`), `RSMainThread::Init()` handles render-side setup:
1. Initializes the per-frame render-side callback (`mainLoop_`)
2. Creates `hgmRenderContext_`, passing the render-to-server connection (in single-process mode, this is `RSRenderToServiceConnection` — a same-process direct callback)
3. Calls `hgmRenderContext_->InitHgmConfig()` to populate member variables
   - **Note**: `InitHgmConfig()` calls `RPHgmXMLParser` to read HGM config independently, similar to the server-side `InitXmlConfig()`. So initialization config is read independently by both sides, but runtime config data flows server→render via IPC every frame

### Per-Frame Runtime

> In single-process mode, the render-to-server connection is a direct in-process call (no cross-process IPC). In multi-process mode, the connection returns immediately — the relevant IPC is not implemented due to a spec-level disable, which is intentional.

Each VSync triggers `mainLoop_()`, which calls `hgmRenderContext_->NotifyRpHgmFrameRate()`:

1. **Render side** populates render-side-only data into `HgmProcessToServiceInfo`
2. **Cross-side call**: `renderToServiceConnection_->NotifyRpHgmFrameRate()` sends `HgmProcessToServiceInfo` to server and executes `HgmContext::ProcessHgmFrameRate()`:
   a. Receives `HgmProcessToServiceInfo` from render side
   b. Populates `HgmServiceToProcessInfo` for return
   c. Determines whether frame rate should be refreshed this frame
   d. Posts task to `HgmTaskHandleThread` → `frameRateManager->UniProcessDataForLtpo()` for LTPO frame-rate decision
   e. Combines external info to compute next-frame rate and sends to hardware layer (details TBD)
3. **Return data**: After server-side callback completes, `HgmServiceToProcessInfo` is returned via the same connection
4. **Render side sync**: Render side calls `SetServiceToProcessInfo()` to sync returned data to member variables
   - `rpHgmConfigData` in `HgmServiceToProcessInfo` triggers the render-side config update callback (`rpFrameRatePolicy_->HgmConfigUpdateCallback()`) only when `hgmDataChangeTypes.test(HGM_CONFIG_DATA)` is true

### External Input

Beyond per-frame flow, HGM receives external IPC input for frame-rate decisions:

1. `rs_interfaces.cpp` receives external calls
2. Dispatched to `rs_render_service_client.cpp` (same-name function)
3. Dispatched to `rs_client_to_service_connection.cpp` (same-name function)
   - Any call that ultimately reaches `hgmContext_` is HGM-related external IPC (e.g., `SetRefreshRateMode`)
   - `hgmContext_` is obtained from `renderServiceAgent_->GetHgmContext()`, which returns a pointer to `renderService_`'s `hgmContext_`
4. Dispatched to `hgm_context.cpp` (same-name function) — most function bodies post tasks via `HgmTaskHandleThread`, ensuring all HGM execution (including frame-rate decisions) is **serial**, avoiding multi-thread concurrency issues

## WHERE TO LOOK

| Task | Location | Notes |
|------|----------|-------|
| Add a new vote source | `core/frame_rate_manager/hgm_frame_rate_manager.h` | Add Handle*Event + VOTER_* in hgm_voter.h |
| Change vote merging logic | `core/utils/hgm_frame_voter.cpp` | ProcessVote/ProcessVoteIter |
| Add new XML config field | `core/utils/hgm_command.h` (struct) → `core/config/xml_parser.cpp` (parse) | PolicyConfigData struct + parser |
| Modify multi-app strategy | `core/frame_rate_manager/hgm_multi_app_strategy.cpp` | UseMax/FollowFocus/UseStrategyNum |
| Change touch idle behavior | `core/frame_rate_manager/hgm_idle_detector.cpp` + `hgm_touch_manager.cpp` | Guaranteed plan + touch state machine |
| Adjust LTPO/DVSync behavior | `core/frame_rate_manager/hgm_frame_rate_manager.cpp` | ProcessLtpoVote, DVSyncTaskProcessor |
| Modify soft VSync per-app rates | `core/soft_vsync_manager/hgm_soft_vsync_manager.cpp` | CollectFrameRateChange |
| Add/modify screen config | `core/hgm_screen_manager/hgm_core.cpp` | Init, AddScreen, SetLtpoConfig |
| Change refresh rate calculation | `core/frame_rate_manager/hgm_frame_rate_manager.cpp` | CalcRefreshRate |
| IPC callback registration | `core/config/hgm_config_callback_manager.cpp` | 3 callback types |
| Test a new feature | `rosen/test/hyper_graphic_manager/unittest/` | Inherit HgmTestBase, use mock_policy_config_visitor.h |

## CODE MAP

| Symbol | Type | Location | Role |
|--------|------|----------|------|
| HgmCore | Singleton class | hgm_screen_manager/hgm_core.h | Top-level entry. Owns HgmFrameRateManager, XMLParser, screens |
| HgmFrameRateManager | Class | frame_rate_manager/hgm_frame_rate_manager.h | Central orchestrator. Owns 8 sub-components |
| HgmFrameVoter | Class | utils/hgm_frame_voter.h | Vote aggregation + LTPO merge |
| HgmVoter | Class | utils/hgm_voter.h | Low-level vote delivery + priority merge |
| VoteInfo | Struct | utils/hgm_voter.h | Single vote: name/min/max/pid |
| HgmMultiAppStrategy | Class | frame_rate_manager/hgm_multi_app_strategy.h | Multi-app conflict resolution |
| HgmIdleDetector | Class | frame_rate_manager/hgm_idle_detector.h | Surface/animation idle detection |
| HgmTouchManager | Class | frame_rate_manager/hgm_touch_manager.h | Touch FSM (inherits HgmStateMachine) |
| HgmPointerManager | Class | frame_rate_manager/hgm_pointer_manager.h | Pointer FSM |
| HgmSoftVSyncManager | Class | soft_vsync_manager/hgm_soft_vsync_manager.h | Per-app VSync rate division |
| HgmVSyncGeneratorController | Class | frame_rate_manager/hgm_vsync_generator_controller.h | VSync rate/offset control |
| HgmEnergyConsumptionPolicy | Singleton | frame_rate_manager/hgm_energy_consumption_policy.h | Power-saving FPS reduction |
| PolicyConfigData | Struct | utils/hgm_command.h | All XML config data (StrategyConfig, ScreenSetting, etc.) |
| PolicyConfigVisitor | Abstract | utils/hgm_command.h | Config query interface |
| XMLParser | Class | config/xml_parser.h | Parses hgm_policy_config.xml |
| HgmScreen | Class (RefBase) | hgm_screen_manager/hgm_screen.h | Screen abstraction with modes |

## CONVENTIONS

- **Naming**: Files `hgm_*.h/cpp`, classes `Hgm*`, enums UPPER_SNAKE_CASE, members trailing `_` (legacy `m` prefix on HgmCore members)
- **Namespace**: `OHOS::Rosen` (newer files) or nested `namespace OHOS { namespace Rosen {` (older files)
- **Logging**: `HGM_LOGD/I/W/E` macros from `config/hgm_log.h` with `%{public}s` privacy format
- **Error returns**: `int32_t` with `HgmErrCode` values (`EXEC_SUCCESS=0`, `HGM_ERROR=-1`), or `bool`
- **Smart pointers**: `sptr<>/wptr<>` for RefBase IPC objects, `shared_ptr`/`unique_ptr` for internal
- **Thread safety**: `std::atomic<T>` for lock-free state, `std::mutex` + `std::lock_guard` for critical sections

## ANTI-PATTERNS

- **DO NOT** access `PolicyConfigData` fields directly from frame_rate_manager/ — use `PolicyConfigVisitor`
- **DO NOT** call `HgmFrameRateManager` directly from render_service — use `HgmContext` (service) or `HgmRenderContext` (render process) facades
- **DO NOT** access the opposite side's objects directly — the server side (HgmCore, HgmContext, HgmFrameRateManager) and the render side (HgmRenderContext) must interact exclusively through the IPC connection (`renderToServiceConnection_` / `RSRenderToServiceConnection`). Neither side may call the other's singletons, members, or functions directly; runtime data flows server→render via `HgmServiceToProcessInfo` IPC every frame, and render→server via `HgmProcessToServiceInfo` IPC
- **DO NOT** modify `currRefreshRate_` without `pendingMutex_` lock
- **DO NOT** skip `HGM_LOGE` before error returns

## UNIQUE STYLES

- Vote priority system: voters_ vector order determines precedence in HgmFrameVoter
- XML-driven policy: all strategies/scenes/modes configured in the XML file returned by `GetHgmXmlPath`.
- 4 dynamic touch modes: TOUCH_DISENABLED, TOUCH_ENABLED, TOUCH_EXT_ENABLED, TOUCH_EXT_ENABLED_LTPO_FIRST
- Pimpl pattern for vendor extension: `HgmUserDefine` → `HgmUserDefineImpl` (friend of HgmCore and HgmFrameRateManager)

## COMMANDS

```bash
# Build HGM library
hb build graphic_2d -i --build-target //foundation/graphic/graphic_2d/rosen/modules/hyper_graphic_manager:libhyper_graphic_manager

# Build all HGM unit tests
hb build graphic_2d -t --build-target //foundation/graphic/graphic_2d/rosen/test/hyper_graphic_manager/unittest:unittest

# Build specific test (frame rate manager)
hb build graphic_2d -t --build-target //foundation/graphic/graphic_2d/rosen/test/hyper_graphic_manager/unittest:frame_rate_manager_test
```

## NOTES

- HgmCore is the singleton root — all external access starts from `HgmCore::Instance()`
- External modules (render_service) interact via facades: `HgmContext` (service process) and `HgmRenderContext` (render process), never directly
- Per-frame integration: `mainLoop_()` → `HgmRenderContext::NotifyRpHgmFrameRate()` → IPC → `HgmContext::ProcessHgmFrameRate()`
- IPC callbacks: 3 types (OnHgmConfigChanged, OnHgmRefreshRateModeChanged, OnHgmRefreshRateUpdate) through `RSIHgmConfigChangeCallback`
- Test infrastructure uses `-Dprivate=public` cflags for direct member access
- Vendor extension point: `graphic_2d_hgm_configs.vendor_root` in GN adds extension sources/maps
