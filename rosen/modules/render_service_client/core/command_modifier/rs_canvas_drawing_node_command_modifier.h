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

#ifndef RENDER_SERVICE_CLIENT_CORE_UI_RS_CANVAS_DRAWING_NODE_COMMAND_MODIFIER_H
#define RENDER_SERVICE_CLIENT_CORE_UI_RS_CANVAS_DRAWING_NODE_COMMAND_MODIFIER_H

#include "command_modifier/rs_command_modifier.h"

namespace OHOS {
namespace Rosen {
class RSCanvasDrawingNode;

struct ResetSurfaceCmdParam {
    int width_;
    int height_;
    uint32_t resetSurfaceIndex_;
};

class ResetSurfaceCmdModifier : public RSCmdModifier {
public:
    static inline constexpr auto Type = RSCmdModifierType::RESET_SURFACE;

    ResetSurfaceCmdModifier(std::weak_ptr<RSNode> node, const ResetSurfaceCmdParam& param)
        : RSCmdModifier(std::move(node)), param_(param)
    {
    }

    RSCmdModifierType GetType() const override
    {
        return Type;
    }

    bool SetParam(const ResetSurfaceCmdParam& param)
    {
        if (param_.width_ == param.width_ &&
            param_.height_ == param.height_ &&
            param_.resetSurfaceIndex_ == param.resetSurfaceIndex_) {
            return true;
        }
        param_ = param;
        return true;
    }

    void UpdateToRender() override;

    RSCmdModifier::UpdateResult UpdateToRenderWithResult() override;

    void DumpParam(std::string& out) const override;

    const ResetSurfaceCmdParam& GetParam() const
    {
        return param_;
    }

private:
    ResetSurfaceCmdParam param_;
};

} // namespace Rosen
} // namespace OHOS

#endif // RENDER_SERVICE_CLIENT_CORE_UI_RS_CANVAS_DRAWING_NODE_COMMAND_MODIFIER_H