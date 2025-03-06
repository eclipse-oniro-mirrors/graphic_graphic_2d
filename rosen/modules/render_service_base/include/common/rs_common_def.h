/*
 * Copyright (c) 2021-2023 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#ifndef RENDER_SERVICE_CLIENT_CORE_COMMON_RS_COMMON_DEF_H
#define RENDER_SERVICE_CLIENT_CORE_COMMON_RS_COMMON_DEF_H

#include <cmath>
#include <functional>
#include <limits>
#include <memory>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <unistd.h>

#include "common/rs_macros.h"

namespace OHOS {
class Surface;

namespace Rosen {
using AnimationId = uint64_t;
using NodeId = uint64_t;
using PropertyId = uint64_t;
using FrameRateLinkerId = uint64_t;
using SurfaceId = uint64_t;
using InteractiveImplictAnimatorId = uint64_t;
using LeashPersistentId = uint64_t;
constexpr uint32_t UNI_MAIN_THREAD_INDEX = UINT32_MAX;
constexpr uint32_t UNI_RENDER_THREAD_INDEX = UNI_MAIN_THREAD_INDEX - 1;
constexpr uint64_t INVALID_NODEID = 0;
constexpr int32_t INSTANCE_ID_UNDEFINED = -1;
constexpr uint32_t RGBA_MAX = 255;
constexpr uint64_t INVALID_LEASH_PERSISTENTID = 0;

// types in the same layer should be 0/1/2/4/8
// types for UINode
enum class RSUINodeType : uint32_t {
    UNKNOW              = 0x0000u,
    RS_NODE             = 0x0001u,
    DISPLAY_NODE        = 0x0011u,
    SURFACE_NODE        = 0x0021u,
    PROXY_NODE          = 0x0041u,
    CANVAS_NODE         = 0x0081u,
    EFFECT_NODE         = 0x0101u,
    ROOT_NODE           = 0x1081u,
    CANVAS_DRAWING_NODE = 0x2081u,
};

enum class FollowType : uint8_t {
    NONE,
    FOLLOW_TO_PARENT,
    FOLLOW_TO_SELF,
};

#define LIKELY(exp) (__builtin_expect((exp) != 0, true))
#define UNLIKELY(exp) (__builtin_expect((exp) != 0, false))

// types for RenderNode
enum class RSRenderNodeType : uint32_t {
    UNKNOW              = 0x0000u,
    RS_NODE             = 0x0001u,
    DISPLAY_NODE        = 0x0011u,
    SURFACE_NODE        = 0x0021u,
    PROXY_NODE          = 0x0041u,
    CANVAS_NODE         = 0x0081u,
    EFFECT_NODE         = 0x0101u,
    ROOT_NODE           = 0x1081u,
    CANVAS_DRAWING_NODE = 0x2081u,
};

// types for Processor
enum class RSProcessorType : uint32_t {
    UNKNOW                          = 0x0000u,
    RS_PROCESSOR                    = 0x0001u,
    PHYSICAL_SCREEN_PROCESSOR       = 0x0011u,
    VIRTUAL_SCREEN_PROCESSOR        = 0x0021u,
    UNIRENDER_PROCESSOR             = 0x0041u,
    UNIRENDER_VIRTUAL_PROCESSOR     = 0x0081u,
};

enum RSRenderParamsDirtyType {
    NO_DIRTY = 0,
    MATRIX_DIRTY,
    LAYER_INFO_DIRTY,
    BUFFER_INFO_DIRTY,
    DRAWING_CACHE_TYPE_DIRTY,
    MAX_DIRTY_TYPE,
};

enum class NodeDirtyType : uint32_t {
    NOT_DIRTY           = 0x0000u,
    GEOMETRY            = 0x0001u,
    BACKGROUND          = 0x0002u,
    CONTENT             = 0x0004u,
    FOREGROUND          = 0x0008u,
    OVERLAY             = 0x0010u,
    APPEARANCE          = 0x0020u,
};

enum class CacheType : uint8_t {
    NONE = 0,
    CONTENT,
    ANIMATE_PROPERTY,
};

enum class DrawableCacheType : uint8_t {
    NONE = 0,
    CONTENT,
};

enum RSDrawingCacheType : uint8_t {
    DISABLED_CACHE = 0,
    FORCED_CACHE,           // must-to-do case
    TARGETED_CACHE,         // suggested case which could be disabled by optimized strategy
    FOREGROUND_FILTER_CACHE // using cache to draw foreground filter
};

enum class FilterCacheType : uint8_t {
    NONE              = 0,
    SNAPSHOT          = 1,
    FILTERED_SNAPSHOT = 2,
    BOTH              = SNAPSHOT | FILTERED_SNAPSHOT,
};

// opinc state
enum NodeCacheState : uint8_t {
    STATE_INIT = 0,
    STATE_CHANGE,
    STATE_UNCHANGE,
    STATE_DISABLE,
};

enum NodeChangeType : uint8_t {
    KEEP_UNCHANGE = 0,
    SELF_DIRTY,
};

// opinc cache state
enum NodeStrategyType : uint8_t {
    CACHE_NONE = 0,
    DDGR_OPINC_DYNAMIC,
    OPINC_AUTOCACHE,
    NODE_GROUP,
    CACHE_DISABLE,
};

enum NodeRecordState : uint8_t {
    RECORD_NONE = 0,
    RECORD_CALCULATE,
    RECORD_CACHING,
    RECORD_CACHED,
    RECORD_DISABLE,
};

enum DrawAreaEnableState : uint8_t {
    DRAW_AREA_INIT = 0,
    DRAW_AREA_ENABLE,
    DRAW_AREA_DISABLE,
};

// priority for node, higher number means lower priority
enum class NodePriorityType : uint8_t {
    MAIN_PRIORITY = 0, // node must render in main thread
    SUB_FOCUSNODE_PRIORITY, // node render in sub thread with the highest priority
    SUB_HIGH_PRIORITY, // node render in sub thread with the second priority
    SUB_LOW_PRIORITY, // node render in sub thread with low priority
};

enum class RSVisibleLevel : uint32_t {
    RS_ALL_VISIBLE = 0,
    RS_SEMI_NONDEFAULT_VISIBLE,
    RS_SEMI_DEFAULT_VISIBLE,
    RS_INVISIBLE,
    RS_SYSTEM_ANIMATE_SCENE,
    RS_UNKNOW_VISIBLE_LEVEL,
};

// status for sub thread node
enum class CacheProcessStatus : uint8_t {
    WAITING = 0, // waiting for process
    DOING, // processing
    DONE, // processed
    SKIPPED, // skip cur process and wait for next new data to process
    UNKNOWN,
};

// the type of surfaceCapture
enum class SurfaceCaptureType : uint8_t {
    DEFAULT_CAPTURE = 0, // displayNode capture or window capture
    UICAPTURE,
};

#ifdef TP_FEATURE_ENABLE
// the type of TpFeatureConfig
enum class TpFeatureConfigType : uint8_t {
    DEFAULT_TP_FEATURE = 0,
    AFT_TP_FEATURE,
};
#endif

struct RSSurfaceCaptureConfig {
    float scaleX = 1.0f;
    float scaleY = 1.0f;
    bool useDma = false;
    bool useCurWindow = true;
    SurfaceCaptureType captureType = SurfaceCaptureType::DEFAULT_CAPTURE;
    bool isSync = false;
};

struct RSSurfaceCapturePermissions {
    bool screenCapturePermission = false;
    bool isSystemCalling = false;
    bool selfCapture = false;
};

enum class DeviceType : uint8_t {
    PHONE,
    PC,
    TABLET,
    OTHERS,
};

enum GrallocBufferAttr : uint32_t {
    // used in set roi region to codec, must be the same as private key in codec
    GRALLOC_BUFFER_ATTR_BUFFER_ROI_INFO = 2054,
};

// types for PC SystemAnimatedScenes
enum class SystemAnimatedScenes : uint32_t {
    ENTER_MISSION_CENTER, // Enter the mission center
    EXIT_MISSION_CENTER, // Exit the mission center
    ENTER_TFS_WINDOW, // Three-finger sliding window recovery
    EXIT_TFU_WINDOW, // The three-finger up window disappears
    ENTER_WINDOW_FULL_SCREEN, // Enter the window full screen
    EXIT_WINDOW_FULL_SCREEN, // Exit the window full screen
    ENTER_MAX_WINDOW, // Enter the window maximization state
    EXIT_MAX_WINDOW, // Exit the window maximization state
    ENTER_SPLIT_SCREEN, // Enter the split screen
    EXIT_SPLIT_SCREEN, // Exit the split screen
    ENTER_APP_CENTER, // Enter the app center
    EXIT_APP_CENTER, // Exit the app center
    APPEAR_MISSION_CENTER, // A special case scenario that displays the mission center
    ENTER_WIND_CLEAR, // Enter win+D in clear screen mode
    ENTER_WIND_RECOVER, // Enter win+D in recover mode
    ENTER_RECENTS, // Enter recents
    EXIT_RECENTS, // Exit recents
    LOCKSCREEN_TO_LAUNCHER, // Enter unlock screen for pc scene
    ENTER_MIN_WINDOW, // Enter the window minimization state
    RECOVER_MIN_WINDOW, // Recover minimized window
    OTHERS, // 1.Default state 2.The state in which the animation ends
};

// types for RSSurfaceRenderNode
enum class RSSurfaceNodeType : uint8_t {
    DEFAULT,
    APP_WINDOW_NODE,          // surfacenode created as app main window
    STARTING_WINDOW_NODE,     // starting window, surfacenode created by wms
    SELF_DRAWING_WINDOW_NODE, // create by wms, such as pointer window and bootanimation
    LEASH_WINDOW_NODE,        // leashwindow
    ABILITY_COMPONENT_NODE,   // surfacenode created as ability component
    SELF_DRAWING_NODE,        // surfacenode created by arkui component (except ability component)
    SURFACE_TEXTURE_NODE,      // create by video
    FOREGROUND_SURFACE,
    SCB_SCREEN_NODE,          // surfacenode created as sceneboard
    UI_EXTENSION_COMMON_NODE, // uiextension node
    UI_EXTENSION_SECURE_NODE, // uiextension node that requires info callback
};

enum class MultiThreadCacheType : uint8_t {
    NONE = 0,
    LEASH_WINDOW,
    ARKTS_CARD,
    NONFOCUS_WINDOW,
};

enum class SelfDrawingNodeType : uint8_t {
    DEFAULT,
    VIDEO,
    XCOM,
};

enum class RSUIFirstSwitch {
    NONE,               // follow RS rules
    MODAL_WINDOW_CLOSE, // open app with modal window animation, close uifirst
    FORCE_DISABLE,      // force close uifirst
    FORCE_ENABLE,       // force open uifirst
    FORCE_ENABLE_LIMIT, // force open uifirst, but is limited by system specification(filter, rotation).
    FORCE_DISABLE_NONFOCUS, // force close uifirst when only in nonfocus window
};

enum class SurfaceWindowType : uint8_t {
    DEFAULT_WINDOW = 0,
    SYSTEM_SCB_WINDOW = 1,
};

struct RSSurfaceRenderNodeConfig {
    NodeId id = 0;
    std::string name = "SurfaceNode";
    std::string bundleName = "";
    RSSurfaceNodeType nodeType = RSSurfaceNodeType::DEFAULT;
    void* additionalData = nullptr;
    bool isTextureExportNode = false;
    bool isSync = false;
    enum SurfaceWindowType surfaceWindowType = SurfaceWindowType::DEFAULT_WINDOW;
};

// codes for arkui-x start
// types for RSSurfaceExt
enum class RSSurfaceExtType : uint8_t {
    NONE,
    SURFACE_TEXTURE,
    SURFACE_PLATFORM_TEXTURE,
};

struct RSSurfaceExtConfig {
    RSSurfaceExtType type = RSSurfaceExtType::NONE;
    void* additionalData = nullptr;
};
using RSSurfaceTextureConfig = RSSurfaceExtConfig;
using RSSurfaceTextureAttachCallBack = std::function<void(int64_t textureId, bool attach)>;
using RSSurfaceTextureUpdateCallBack = std::function<void(std::vector<float>&)>;
using RSSurfaceTextureInitTypeCallBack = std::function<void(int32_t&)>;
// codes for arkui-x end

struct RSDisplayNodeConfig {
    uint64_t screenId = 0;
    bool isMirrored = false;
    NodeId mirrorNodeId = 0;
    bool isSync = false;
};

// ability state of surface node
enum class RSSurfaceNodeAbilityState : uint8_t {
    BACKGROUND,
    FOREGROUND,
};

struct SubSurfaceCntUpdateInfo {
    int updateCnt_ = 0;
    NodeId preParentId_ = INVALID_NODEID;
    NodeId curParentId_ = INVALID_NODEID;
};

constexpr int64_t NS_TO_S = 1000000000;
constexpr int64_t NS_PER_MS = 1000000;
constexpr uint32_t SIZE_UPPER_LIMIT = 1000;
constexpr uint32_t PARTICLE_EMMITER_UPPER_LIMIT = 2000;
constexpr uint32_t PARTICLE_UPPER_LIMIT = 1000000;

#if defined(M_PI)
constexpr float PI = M_PI;
#else
static const float PI = std::atanf(1.0) * 4;
#endif

template<typename T>
inline constexpr bool ROSEN_EQ(const T& x, const T& y)
{
    if constexpr (std::is_floating_point<T>::value) {
        return (std::abs((x) - (y)) <= (std::numeric_limits<T>::epsilon()));
    } else {
        return x == y;
    }
}

template<typename T>
inline bool ROSEN_EQ(T x, T y, T epsilon)
{
    return (std::abs((x) - (y)) <= (epsilon));
}

template<typename T>
inline bool ROSEN_EQ(const std::weak_ptr<T>& x, const std::weak_ptr<T>& y)
{
    return !(x.owner_before(y) || y.owner_before(x));
}

inline bool ROSEN_LNE(float left, float right) // less not equal
{
    constexpr float epsilon = -0.001f;
    return (left - right) < epsilon;
}

inline bool ROSEN_GNE(float left, float right) // great not equal
{
    constexpr float epsilon = 0.001f;
    return (left - right) > epsilon;
}

inline bool ROSEN_GE(float left, float right) // great or equal
{
    constexpr float epsilon = -0.001f;
    return (left - right) > epsilon;
}

inline bool ROSEN_LE(float left, float right) // less or equal
{
    constexpr float epsilon = 0.001f;
    return (left - right) < epsilon;
}

class MemObject {
public:
    explicit MemObject(size_t size) : size_(size) {}
    virtual ~MemObject() = default;

    void* operator new(size_t size);
    void operator delete(void* ptr);

    void* operator new(std::size_t size, const std::nothrow_t&) noexcept;
    void operator delete(void* ptr, const std::nothrow_t&) noexcept;

protected:
    size_t size_;
};

inline constexpr pid_t ExtractPid(uint64_t id)
{
    // extract high 32 bits of nodeid/animationId/propertyId as pid
    return static_cast<pid_t>(id >> 32);
}

template<class Container, class Predicate>
inline typename Container::size_type EraseIf(Container& container, Predicate pred)
{
    // erase from container if pred returns true, backport of c++20 std::remove_if
    typename Container::size_type oldSize = container.size();
    const typename Container::iterator end = container.end();
    for (typename Container::iterator iter = container.begin(); iter != end;) {
        if (pred(*iter)) {
            iter = container.erase(iter);
        } else {
            ++iter;
        }
    }
    return oldSize - container.size();
}

enum class AncoFlags : uint32_t {
    IS_ANCO_NODE = 0x0001
};

enum class RSInterfaceErrorCode : uint32_t {
#undef NO_ERROR
    NO_ERROR = 0,
    NONSYSTEM_CALLING,
    NOT_SELF_CALLING,
    WRITE_PARCEL_ERROR,
    UNKNOWN_ERROR,
};

} // namespace Rosen
} // namespace OHOS
#endif // RENDER_SERVICE_CLIENT_CORE_COMMON_RS_COMMON_DEF_H
