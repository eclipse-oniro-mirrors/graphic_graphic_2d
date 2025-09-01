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

#ifndef RENDER_SERVICE_CLIENT_CORE_PIPELINE_RS_DRAW_CMD_LIST_H
#define RENDER_SERVICE_CLIENT_CORE_PIPELINE_RS_DRAW_CMD_LIST_H

#include "recording/draw_cmd_list.h"

#include "draw/canvas.h"
#include "utils/rect.h"

namespace OHOS {
namespace Rosen {
namespace Drawing {
class DrawCmdList;
class Canvas;
} // namespace Drawing

struct DrawCmdListOpacity {
    float startOpacity;
    float endOpacity;
    float opacity;
    float lastOpacity;

    DrawCmdListOpacity() : startOpacity(0.f), endOpacity(1.f), opacity(0.f), lastOpacity(0.f) {}
    DrawCmdListOpacity(float start, float end, float current, float last)
        : startOpacity(start), endOpacity(end), opacity(current), lastOpacity(last)
    {}
};

class RSB_EXPORT RSDrawCmdList : public Drawing::DrawCmdList {
public:
    /**
     * @brief   Creates a RSDrawCmdList
     */
    RSDrawCmdList() = default;
    /**
     * @brief   Destroy a RSDrawCmdList
     */
    ~RSDrawCmdList() override
    {
        startValue_.first.reset();
        endValue_.first.reset();
    };

    bool IsEmpty() const override;

    void Estimate(float fraction);

    friend bool operator==(const std::shared_ptr<RSDrawCmdList>& lhs, const std::shared_ptr<RSDrawCmdList>& rhs)
    {
        return false;
    }

    friend std::shared_ptr<RSDrawCmdList> operator+(
        const std::shared_ptr<RSDrawCmdList>& lhs, const std::shared_ptr<RSDrawCmdList>& rhs)
    {
        return lhs;
    }

    friend std::shared_ptr<RSDrawCmdList> operator-(
        const std::shared_ptr<RSDrawCmdList>& lhs, const std::shared_ptr<RSDrawCmdList>& rhs)
    {
        return lhs;
    }

    friend std::shared_ptr<RSDrawCmdList> operator*(const std::shared_ptr<RSDrawCmdList>& lhs, float rhs)
    {
        return lhs;
    }

    void InitAnimationValue(
        const std::shared_ptr<Drawing::DrawCmdList> startValue, const std::shared_ptr<Drawing::DrawCmdList> endValue);

    /**
     * @brief  Gets the width of the RSDrawCmdList.
     */
    int32_t GetWidth() const override;

    /**
     * @brief  Gets the height of the RSDrawCmdList.
     */
    int32_t GetHeight() const override;

    void Playback(Drawing::Canvas& canvas, const Drawing::Rect* rect = nullptr) override;
    std::shared_ptr<Drawing::DrawCmdList> GetEndDrawCmdList() const override;

    std::string ToString() const;

private:
    void CleanOpacity();

    std::pair<std::shared_ptr<Drawing::DrawCmdList>, DrawCmdListOpacity> startValue_;
    std::pair<std::shared_ptr<Drawing::DrawCmdList>, DrawCmdListOpacity> endValue_;
};
using RSDrawCmdListPtr = std::shared_ptr<RSDrawCmdList>;
} // namespace Rosen
} // namespace OHOS
#endif // RENDER_SERVICE_CLIENT_CORE_PIPELINE_RS_DRAW_CMD_LIST_H
