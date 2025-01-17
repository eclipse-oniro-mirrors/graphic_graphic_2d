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
#include "utils/picture_recorder.h"

#include "impl_factory.h"

namespace OHOS {
namespace Rosen {
namespace Drawing {

PictureRecorder::PictureRecorder() noexcept : pictureRecorderImplPtr_(ImplFactory::CreatePictureRecorderImpl()) {}

std::shared_ptr<Canvas> PictureRecorder::BeginRecording(float width, float height)
{
    return pictureRecorderImplPtr_->BeginRecording(width, height);
}

std::shared_ptr<Picture> PictureRecorder::FinishRecordingAsPicture()
{
    return pictureRecorderImplPtr_->FinishRecordingAsPicture();
}
} // namespace Drawing
} // namespace Rosen
} // namespace OHOS