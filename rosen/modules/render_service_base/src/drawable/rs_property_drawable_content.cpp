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

#include "drawable/rs_property_drawable_content.h"

#include "pipeline/rs_paint_filter_canvas.h"
#include "pipeline/rs_recording_canvas.h"
#include "pipeline/rs_render_node.h"
#include "platform/common/rs_log.h"
#include "property/rs_properties_painter.h"

namespace OHOS::Rosen {

void RSPropertyDrawableContent::OnSync()
{
    if (!needSync_) {
        return;
    }
    drawCmdList_ = std::move(stagingDrawCmdList_);
    needSync_ = false;
}

RSDrawable::Ptr RSPropertyDrawableContent::CreateDrawable() const
{
    auto ptr = std::static_pointer_cast<const RSPropertyDrawableContent>(shared_from_this());
    return std::make_shared<RSPropertyDrawableNG>(ptr);
}

class RSPropertyDrawCmdListRecorder {
public:
    // not copyable and moveable
    RSPropertyDrawCmdListRecorder(const RSPropertyDrawCmdListRecorder&) = delete;
    RSPropertyDrawCmdListRecorder(const RSPropertyDrawCmdListRecorder&&) = delete;
    RSPropertyDrawCmdListRecorder& operator=(const RSPropertyDrawCmdListRecorder&) = delete;
    RSPropertyDrawCmdListRecorder& operator=(const RSPropertyDrawCmdListRecorder&&) = delete;

    explicit RSPropertyDrawCmdListRecorder(int width, int height)
    {
        // PLANNING: use RSRenderNode to determine the correct recording canvas size
        recordingCanvas_ = std::make_unique<ExtendRecordingCanvas>(width, height, true);
        // PLANNING: add something like RSPaintNoFilter that inherits from RSPaintFilterCanvas
        paintFilterCanvas_ = std::make_unique<RSPaintFilterCanvas>(recordingCanvas_.get());
    }

    virtual ~RSPropertyDrawCmdListRecorder()
    {
        if (paintFilterCanvas_) {
            ROSEN_LOGE("Object destroyed without calling EndRecording.");
        }
    }

    const std::unique_ptr<RSPaintFilterCanvas>& GetPaintFilterCanvas() const
    {
        return paintFilterCanvas_;
    }

    const std::unique_ptr<ExtendRecordingCanvas>& GetRecordingCanvas() const
    {
        return recordingCanvas_;
    }

    std::shared_ptr<Drawing::DrawCmdList>&& EndRecordingAndReturnRecordingList()
    {
        auto displayList = recordingCanvas_->GetDrawCmdList();
        paintFilterCanvas_.reset();
        recordingCanvas_.reset();
        return std::move(displayList);
    }

protected:
    std::unique_ptr<ExtendRecordingCanvas> recordingCanvas_;
    std::unique_ptr<RSPaintFilterCanvas> paintFilterCanvas_;
};

class RSPropertyDrawCmdListUpdater : public RSPropertyDrawCmdListRecorder {
public:
    explicit RSPropertyDrawCmdListUpdater(int width, int height, RSPropertyDrawableContent* target)
        : RSPropertyDrawCmdListRecorder(width, height), target_(target)
    {}
    ~RSPropertyDrawCmdListUpdater() override
    {
        if (recordingCanvas_) {
            target_->stagingDrawCmdList_ = EndRecordingAndReturnRecordingList();
            target_->needSync_ = true;
        } else {
            ROSEN_LOGE("Update failed, recording canvas is null!");
        }
    }

private:
    RSPropertyDrawableContent* target_;
};

RSDrawableContent::Ptr RSBackgroundContent::OnGenerate(const RSRenderNode& node)
{
    RSPropertyDrawCmdListRecorder generator(0, 0);
    RSPropertiesPainter::DrawBackground(node.GetRenderProperties(), *generator.GetPaintFilterCanvas());
    return std::make_unique<RSBackgroundContent>(generator.EndRecordingAndReturnRecordingList());
};

bool RSBackgroundContent::OnUpdate(const RSRenderNode& node)
{
    // regenerate stagingDrawCmdList_
    RSPropertyDrawCmdListUpdater updater(0, 0, this);
    RSPropertiesPainter::DrawBackground(node.GetRenderProperties(), *updater.GetPaintFilterCanvas());
    return true;
}

RSDrawableContent::Ptr RSBorderContent::OnGenerate(const RSRenderNode& node)
{
    RSPropertyDrawCmdListRecorder generator(0, 0);
    RSPropertiesPainter::DrawBorder(node.GetRenderProperties(), *generator.GetPaintFilterCanvas());
    return std::make_unique<RSBorderContent>(generator.EndRecordingAndReturnRecordingList());
};

bool RSBorderContent::OnUpdate(const RSRenderNode& node)
{
    // regenerate stagingDrawCmdList_
    RSPropertyDrawCmdListUpdater updater(0, 0, this);
    RSPropertiesPainter::DrawBorder(node.GetRenderProperties(), *updater.GetPaintFilterCanvas());
    return true;
}

} // namespace OHOS::Rosen
