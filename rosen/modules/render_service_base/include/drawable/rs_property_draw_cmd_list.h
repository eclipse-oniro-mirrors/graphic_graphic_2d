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

#ifndef RENDER_SERVICE_BASE_DRAWABLE_RS_PROPERTY_DRAW_CMD_LIST_H
#define RENDER_SERVICE_BASE_DRAWABLE_RS_PROPERTY_DRAW_CMD_LIST_H

#include <memory>

#include "recording/draw_cmd_list.h"

namespace OHOS::Rosen {
class RSRenderNode;

class RSPropertyDrawCmdList {
public:
    RSPropertyDrawCmdList(std::shared_ptr<Drawing::DrawCmdList>&& drawCmdList) : drawCmdList_(std::move(drawCmdList)) {}
    virtual ~RSPropertyDrawCmdList() = default;

    // type definition
    using Ptr = std::unique_ptr<RSPropertyDrawCmdList>;
    // using Vec = std::array<Ptr, static_cast<size_t>(RSPropertyDrawCmdListSlot::MAX)>;
    // using Generator = std::function<Ptr(const RSRenderContent&)>;

    // every child class should have this
    // static RSPropertyDrawCmdList::Ptr OnGenerate(const RSRenderNode& node) { return nullptr; };

    // return true if this drawable can be updated thus not need to recreate, default to false
    virtual bool OnUpdate(const RSRenderNode& node)
    {
        return false;
    }

    //
    void OnSync();

protected:
    bool needSync_ = false;
    std::shared_ptr<Drawing::DrawCmdList> drawCmdList_;
    std::shared_ptr<Drawing::DrawCmdList> stagingDrawCmdList_;

    friend class RSPropertyDrawCmdListUpdater;
    friend class RSPropertyDrawableNG;
};

// DEMO
class RSBackgroundDrawCmdList : public RSPropertyDrawCmdList {
public:
    static RSPropertyDrawCmdList::Ptr OnGenerate(const RSRenderNode& node);
    bool OnUpdate(const RSRenderNode& node) override;
};

// DEMO
class RSBorderDrawCmdList : public RSPropertyDrawCmdList {
public:
    static RSPropertyDrawCmdList::Ptr OnGenerate(const RSRenderNode& node);
    bool OnUpdate(const RSRenderNode& node) override;
};

} // namespace OHOS::Rosen
#endif // RENDER_SERVICE_BASE_DRAWABLE_RS_PROPERTY_DRAW_CMD_LIST_H
