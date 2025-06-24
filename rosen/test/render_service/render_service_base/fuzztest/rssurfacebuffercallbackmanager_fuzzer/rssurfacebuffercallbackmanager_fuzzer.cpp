#include "rssurfacebuffercallbackmanager_fuzzer.h"
#include "pipeline/rs_surface_buffer_callback_manager.h"

#include <stddef.h>
#include <stdint.h>

namespace OHOS::Rosen {
namespace {
const uint8_t* g_data = nullptr;
size_t g_size = 0;
size_t g_pos;
} // namespace

template<class T>
T GetData()
{
    T object {};
    size_t objectSize = sizeof(object);
    if (g_data == nullptr || objectSize > g_size - g_pos) {
        return object;
    }
    errno_t ret = memcpy_s(&object, objectSize, g_data + g_pos, objectSize);
    if (ret != EOK) {
        return {};
    }
    g_pos += objectSize;
    return object;
}

bool SetVSyncFuncs(const uint8_t* data, size_t size)
{
    if (data == nullptr) {
        return false;
    }

    // initialize
    g_data = data;
    g_size = size;
    g_pos = 0;
    RSSurfaceBufferCallbackManager::VSyncFuncs vSyncFuncs;
    RSSurfaceBufferCallbackManager::Instance().SetVSyncFuncs(vSyncFuncs);
    return true;
}

bool SetIsUniRender(const uint8_t* data, size_t size)
{
    if (data == nullptr) {
        return false;
    }

    // initialize
    g_data = data;
    g_size = size;
    g_pos = 0;
    RSSurfaceBufferCallbackManager::Instance().SetIsUniRender(false);
    return true;
}

#ifdef RS_ENABLE_VK
bool SetReleaseFenceForVulkan(const uint8_t* data, size_t size)
{
    if (data == nullptr) {
        return false;
    }

    // initialize
    g_data = data;
    g_size = size;
    g_pos = 0;
    int releaseFenceFd = 0;
    NodeId rootNodeId = static_cast<NodeId>(0);
    RSSurfaceBufferCallbackManager::Instance().SetReleaseFenceForVulkan(releaseFenceFd, rootNodeId);
    return true;
}

bool RunSurfaceBufferSubCallbackForVulkan(const uint8_t* data, size_t size)
{
    if (data == nullptr) {
        return false;
    }

    // initialize
    g_data = data;
    g_size = size;
    g_pos = 0;
    int releaseFenceFd = 0;
    NodeId nodeId = static_cast<NodeId>(0);
    RSSurfaceBufferCallbackManager::Instance().RunSurfaceBufferSubCallbackForVulkan(nodeId);
    return true;
}
#endif

bool RegisterSurfaceBufferCallback(const uint8_t* data, size_t size)
{
    if (data == nullptr) {
        return false;
    }

    // initialize
    g_data = data;
    g_size = size;
    g_pos = 0;

    pid_t pid = 0;
    uint64_t uid = 0;
    sptr<RSISurfaceBufferCallback> callback;
    RSSurfaceBufferCallbackManager::Instance().RegisterSurfaceBufferCallback(pid, uid, callback);
    return true;
}

bool UnregisterSurfaceBufferCallback(const uint8_t* data, size_t size)
{
    if (data == nullptr) {
        return false;
    }

    // initialize
    g_data = data;
    g_size = size;
    g_pos = 0;

    pid_t pid = 0;
    uint64_t uid= 0;
    RSSurfaceBufferCallbackManager::Instance().UnregisterSurfaceBufferCallback(pid);
    RSSurfaceBufferCallbackManager::Instance().UnregisterSurfaceBufferCallback(pid, uid);
    return true;
}

#ifdef ROSEN_OHOS
bool GetOnFinishCb(const uint8_t* data, size_t size)
{
    if (data == nullptr) {
        return false;
    }

    // initialize
    g_data = data;
    g_size = size;
    g_pos = 0;
    RSSurfaceBufferCallbackManager::Instance().GetOnFinishCb();
    
    return true;
}

bool GetOnAfterAcquireBufferCb(const uint8_t* data, size_t size)
{
    if (data == nullptr) {
        return false;
    }

    // initialize
    g_data = data;
    g_size = size;
    g_pos = 0;
    RSSurfaceBufferCallbackManager::Instance().GetOnAfterAcquireBufferCb();
    
    return true;
}
#endif


} // namespace OHOS::Rosen

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::Rosen::SetVSyncFuncs(data, size);
    OHOS::Rosen::SetIsUniRender(data, size);
#ifdef RS_ENABLE_VK
    OHOS::Rosen::SetReleaseFenceForVulkan(data, size);
    OHOS::Rosen::RunSurfaceBufferSubCallbackForVulkan(data, size);
#endif
    OHOS::Rosen::RegisterSurfaceBufferCallback(data, size);
    OHOS::Rosen::UnregisterSurfaceBufferCallback(data, size);
#ifdef ROSEN_OHOS
    OHOS::Rosen::GetOnFinishCb(data, size);
    OHOS::Rosen::GetOnAfterAcquireBufferCb(data, size);
#endif
    return 0;
}