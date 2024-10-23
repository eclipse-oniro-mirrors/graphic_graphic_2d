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
#ifndef RENDER_SERVICE_CLIENT_CORE_UI_RS_TEXTURE_EXPORT_H
#define RENDER_SERVICE_CLIENT_CORE_UI_RS_TEXTURE_EXPORT_H

#include "ui/rs_ui_director.h"
#include "ui/rs_node.h"

namespace OHOS {
namespace Rosen {

class RSC_EXPORT RSTextureExport {
public:
    RSTextureExport(std::shared_ptr<RSNode> rootNode, SurfaceId surfaceId);
    ~RSTextureExport();
    bool DoTextureExport();
    void StopTextureExport();
    void UpdateBufferInfo(float x, float y, float width, float height);
private:
    std::shared_ptr<RSUIDirector> rsUiDirector_;
    std::shared_ptr<RSNode> rootNode_;
    SurfaceId surfaceId_;
    std::shared_ptr<RSSurfaceNode> virtualSurfaceNode_;
    std::shared_ptr<RSNode> virtualRootNode_;
};
} // namespace Rosen
} // namespace OHOS

#endif // RENDER_SERVICE_CLIENT_CORE_UI_RS_TEXTURE_EXPORT_H
