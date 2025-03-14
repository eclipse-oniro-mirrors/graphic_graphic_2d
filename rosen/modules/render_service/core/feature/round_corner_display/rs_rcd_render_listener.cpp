/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "rs_rcd_render_listener.h"

#include "pipeline/main_thread/rs_main_thread.h"
#include "platform/common/rs_log.h"

namespace OHOS {
namespace Rosen {
RSRcdRenderListener::~RSRcdRenderListener() {}

RSRcdRenderListener::RSRcdRenderListener(std::weak_ptr<RSSurfaceHandler> surfaceHandler)
    : surfaceHandler_(surfaceHandler) {}

void RSRcdRenderListener::OnBufferAvailable()
{
    auto surfaceHandler = surfaceHandler_.lock();
    if (surfaceHandler == nullptr) {
        RS_LOGE("RSRcdRenderListener::OnBufferAvailable surfaceHandler is nullptr");
        return;
    }
    surfaceHandler->IncreaseAvailableBuffer();
}

void RSRcdRenderListener::OnGoBackground()
{
    std::weak_ptr<RSSurfaceHandler> surfaceHandler = surfaceHandler_;
    RSMainThread::Instance()->PostTask([surfaceHandler]() {
        auto hanlder = surfaceHandler.lock();
        if (hanlder == nullptr) {
            RS_LOGW("RSRcdRenderListener::OnGoBackground surfaceHandler is nullptr");
            return;
        }
        hanlder->ResetBufferAvailableCount();
        hanlder->CleanCache();
    });
}
} // namespace Rosen
} // namespace OHOS