/*
 * Copyright (c) 2022-2025 Huawei Device Co., Ltd.
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

#include "pipeline/main_thread/rs_uni_render_listener.h"

#include "common/rs_common_def.h"
#include "pipeline/main_thread/rs_main_thread.h"
#include "platform/common/rs_log.h"

#undef LOG_TAG
#define LOG_TAG "RSUniRenderListener"

namespace OHOS {
namespace Rosen {
RSUniRenderListener::~RSUniRenderListener() {}

RSUniRenderListener::RSUniRenderListener(std::weak_ptr<RSSurfaceHandler> surfaceHandler)
    : surfaceHandler_(surfaceHandler) {}

void RSUniRenderListener::OnBufferAvailable()
{
    auto surfaceHandler = surfaceHandler_.lock();
    if (surfaceHandler == nullptr) {
        RS_LOGE("OnBufferAvailable surfaceHandler is nullptr");
        return;
    }
    RS_LOGD("OnBufferAvailable node id:%{public}" PRIu64, surfaceHandler->GetNodeId());
    surfaceHandler->IncreaseAvailableBuffer();
}
}
}
