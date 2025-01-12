/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#ifndef SKIA_PICTURE_RECORDER_H
#define SKIA_PICTURE_RECORDER_H

#include "impl_interface/picture_recorder_impl.h"
#include "include/core/SkPictureRecorder.h"

namespace OHOS {
namespace Rosen {
namespace Drawing {

class SkiaPictureRecorder : public PictureRecorderImpl {
public:
    static inline constexpr AdapterType TYPE = AdapterType::SKIA_ADAPTER;
    SkiaPictureRecorder() noexcept;
    ~SkiaPictureRecorder() override
    {
        delete skPictureRecorder_;
    }

    AdapterType GetType() const override
    {
        return AdapterType::SKIA_ADAPTER;
    }

    SkPictureRecorder* GetPictureRecorder() const;
    std::shared_ptr<Canvas> BeginRecording(float width, float height) override;
    std::shared_ptr<Picture> FinishRecordingAsPicture() override;

private:
    SkPictureRecorder* skPictureRecorder_;
};
} // namespace Drawing
} // namespace Rosen
} // namespace OHOS
#endif