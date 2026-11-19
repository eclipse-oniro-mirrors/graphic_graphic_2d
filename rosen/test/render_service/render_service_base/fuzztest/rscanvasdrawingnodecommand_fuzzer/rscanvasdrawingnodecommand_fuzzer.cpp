/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include "rscanvasdrawingnodecommand_fuzzer.h"

#include <cstddef>
#include <cstdint>
#include <fuzzer/FuzzedDataProvider.h>
#include <securec.h>

#include "command/rs_canvas_drawing_node_command.h"
#include "common/rs_background_thread.h"
#include "common/rs_common_def.h"
#include "pipeline/rs_render_node_gc.h"
#include "platform/common/rs_system_properties.h"

namespace OHOS {
namespace Rosen {
bool DoCanvasDrawingNodeCommand(FuzzedDataProvider& fdp)
{
    RSContext context;
    NodeId id = fdp.ConsumeIntegral<NodeId>();
    bool isTextureExportNode = fdp.ConsumeBool();
    uint64_t token = fdp.ConsumeIntegral<uint64_t>();
    int32_t width = fdp.ConsumeIntegral<int32_t>();
    int32_t height = fdp.ConsumeIntegral<int32_t>();
    uint32_t resetSurfaceIndex = fdp.ConsumeIntegral<uint32_t>();

    RSCanvasDrawingNodeCommandHelper::Create(context, id, isTextureExportNode, token);
    RSCanvasDrawingNodeCommandHelper::ResetSurface(context, id, width, height, resetSurfaceIndex);
    context.GetMutableNodeMap().FilterNodeByPid(getpid(), true);
    RSRenderNodeGC::Instance().ReleaseNodeMemory(true);
    // Node destruction is posted to RSBackgroundThread asynchronously. Wait for the queue to be
    // drained here, otherwise the background delete may overlap with the next iteration's node-map
    // traversal on the fuzzer thread, which ASan reports as heap-use-after-free.
    if (RSSystemProperties::GetBgNodeReleaseEnabled()) {
        RSBackgroundThread::Instance().PostSyncTask([]() {});
    }
    return true;
}
} // namespace Rosen
} // namespace OHOS

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    FuzzedDataProvider fdp(data, size);
    OHOS::Rosen::DoCanvasDrawingNodeCommand(fdp);
    return 0;
}
