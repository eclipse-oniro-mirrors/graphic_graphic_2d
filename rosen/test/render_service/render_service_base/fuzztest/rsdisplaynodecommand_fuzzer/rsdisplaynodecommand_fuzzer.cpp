/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "rsdisplaynodecommand_fuzzer.h"

#include <cstddef>
#include <cstdint>
#include <securec.h>

#include "command/rs_display_node_command.h"
#include "pipeline/rs_render_node_gc.h"
#include "pipeline/rs_screen_render_node.h"
#include "screen_manager/rs_screen_property.h"

namespace OHOS {
namespace Rosen {
namespace {
const uint8_t* g_data = nullptr;
size_t g_size = 0;
size_t g_pos;
constexpr ScreenId TEST_SCREEN_ID = 1;
constexpr NodeId TEST_SCREEN_NODE_ID = 100;
constexpr NodeId TEST_DISPLAY_NODE_ID = 1;

void RegisterScreenNode(RSContext& context)
{
    auto screenRenderNode = std::make_shared<RSScreenRenderNode>(TEST_SCREEN_NODE_ID, TEST_SCREEN_ID,
        context.weak_from_this());
    RSScreenProperty property;
    property.Set(ScreenPropertyType::IS_VIRTUAL, sptr<ScreenProperty<bool>>::MakeSptr(true));
    screenRenderNode->SetScreenProperty(property);
    context.GetMutableNodeMap().RegisterRenderNode(screenRenderNode);
}
} // namespace

/*
 * describe: get data from outside untrusted data(g_data) which size is according to sizeof(T)
 * tips: only support basic type
 */
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

RSWindowRecordConfig GetWindowRecordConfigFromData()
{
    RSWindowRecordConfig recordConfig;
    recordConfig.renderFit = GetData<bool>() ? WindowRecordFit::ASPECT_FIT : WindowRecordFit::ASPECT_FIT_TOP_LEFT;
    // Bounded id count; includes the over-cap MAX_WINDOW_RECORD_SURFACE_NUM + 1 value.
    size_t idCount = GetData<uint16_t>() % (MAX_WINDOW_RECORD_SURFACE_NUM + 2);
    for (size_t i = 0; i < idCount; ++i) {
        recordConfig.surfaceNodeIds.push_back(GetData<NodeId>());
    }
    return recordConfig;
}

bool DoDisplayNode(const uint8_t* data, size_t size, RSContext& context)
{
    if (data == nullptr) {
        return false;
    }

    // test
    NodeId id = GetData<NodeId>();
    uint64_t screenId = GetData<uint64_t>();
    DisplayMode displayMode = GetData<DisplayMode>();
    NodeId mirrorNodeId = GetData<NodeId>();
    bool isSync = GetData<bool>();
    uint32_t mirrorSourceRotation = GetData<uint32_t>();
    float positionZ = GetData<float>();
    RSDisplayNodeConfig config = { screenId, displayMode, mirrorNodeId, isSync, mirrorSourceRotation, positionZ };
    bool isSecurityDisplay = GetData<bool>();
    bool isBootAnimation = GetData<bool>();
    NodeId id2 = GetData<NodeId>();
    ScreenRotation screenRotation = GetData<ScreenRotation>();
    DisplayNodeCommandHelper::Create(context, id, config);
    DisplayNodeCommandHelper::SetScreenId(context, id, screenId);
    DisplayNodeCommandHelper::SetSecurityDisplay(context, id, isSecurityDisplay);
    DisplayNodeCommandHelper::SetDisplayMode(context, id, config);
    DisplayNodeCommandHelper::SetBootAnimation(context, id, isBootAnimation);
    DisplayNodeCommandHelper::SetBootAnimation(context, id2, isBootAnimation);
    DisplayNodeCommandHelper::SetScreenRotation(context, id, screenRotation);
    return true;
}
bool DoSetDisplayMode(const uint8_t* data, size_t size, RSContext& context)
{
    if (data == nullptr) {
        return false;
    }

    NodeId id = GetData<NodeId>();
    RSDisplayNodeConfig config { 0, DisplayMode::EXPAND, 0};
    DisplayNodeCommandHelper::SetDisplayMode(context, id, config);

    DisplayNodeCommandHelper::Create(context, id, config);
    DisplayNodeCommandHelper::SetDisplayMode(context, id, config);

    config.displayMode = DisplayMode::MIRROR;
    DisplayNodeCommandHelper::SetDisplayMode(context, id, config);

    NodeId mirrorNodeId = GetData<NodeId>();
    config.mirrorNodeId = mirrorNodeId;
    DisplayNodeCommandHelper::Create(context, mirrorNodeId, config);
    DisplayNodeCommandHelper::SetDisplayMode(context, id, config);

    return true;
}
bool DoSetBootAnimation(const uint8_t* data, size_t size, RSContext& context)
{
    if (data == nullptr) {
        return false;
    }

    NodeId id = GetData<NodeId>();
    NodeId rID = GetData<NodeId>();
    RSDisplayNodeConfig config { 0, DisplayMode::MIRROR, 0};
    DisplayNodeCommandHelper::Create(context, id, config);
    DisplayNodeCommandHelper::SetBootAnimation(context, id, true);
    DisplayNodeCommandHelper::SetBootAnimation(context, rID, true);

    return true;
}

bool DoSetVirtualScreenMuteStatus(const uint8_t* data, size_t size, RSContext& context)
{
    if (data == nullptr) {
        return false;
    }

    NodeId id = GetData<NodeId>();
    bool muteStatus = GetData<bool>();
    DisplayNodeCommandHelper::SetVirtualScreenMuteStatus(context, id, muteStatus);

    return true;
}

bool DoSetWindowRecordConfig()
{
    // A dedicated context keeps the fixed virtual screen and display away from the random fixtures above.
    std::shared_ptr<RSContext> context = std::make_shared<RSContext>();
    RegisterScreenNode(*context);
    RSDisplayNodeConfig displayConfig;
    displayConfig.screenId = TEST_SCREEN_ID;
    DisplayNodeCommandHelper::Create(*context, TEST_DISPLAY_NODE_ID, displayConfig);

    RSWindowRecordConfig recordConfig = GetWindowRecordConfigFromData();
    DisplayNodeCommandHelper::SetWindowRecordConfig(*context, TEST_DISPLAY_NODE_ID, recordConfig);

    context = nullptr;
    RSRenderNodeGC::Instance().ReleaseNodeMemory();
    return true;
}
} // namespace Rosen
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    // initialize
    OHOS::Rosen::g_data = data;
    OHOS::Rosen::g_size = size;
    OHOS::Rosen::g_pos = 0;

    std::shared_ptr<OHOS::Rosen::RSContext> context = std::make_shared<OHOS::Rosen::RSContext>();

    /* Run your code on data */
    OHOS::Rosen::DoDisplayNode(data, size, *context);
    OHOS::Rosen::DoSetDisplayMode(data, size, *context);
    OHOS::Rosen::DoSetBootAnimation(data, size, *context);
    OHOS::Rosen::DoSetVirtualScreenMuteStatus(data, size, *context);
    OHOS::Rosen::DoSetWindowRecordConfig();

    context = nullptr;
    OHOS::Rosen::RSRenderNodeGC::Instance().ReleaseNodeMemory();

    return 0;
}
