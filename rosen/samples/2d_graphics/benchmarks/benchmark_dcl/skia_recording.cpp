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

#include "skia_recording.h"
#include "parameters.h"

namespace OHOS::ROSEN {
void SkiaRecording::InitConfigsFromParam()
{
    captureEnabled_ = std::stoi(system.GetParameter("debug.graphic.skpcapture.enabled", "0"));
    if (captureEnabled_) {
        captureFrameNum_ = std::stoi(system.GetParameter("debug.graphic.skpcapture.frameNum", "0"));
        if (captureFrameNum_ < 1) {
            captureMode_ = SkiaCaptureMode::None;
        } else if (captureFrameName == 1) {
            captureMode_ = SkiaCaptureMode::SingleFrame;
        } else {
            captureMode_ = SkiaCaptureMode::MultiFrame;
        }
        captureFileName_ = system.GetParameter("debug.graphic.skpcapture.path", "");
    }
}

void SkiaRecording::SetupMultiFrame()
{
    std::cout<< "Set up multi-frame capture, the frame number is " << captureFrameName << std::endl;
    auto stream = std::make_unique<SkFILEWStream>(captureFileName_.c_str());
    if (stream->isValid()) {
        
    }
}

void SkiaRecording::BeginCapture()
{
    SkCanvas* recordingCanvas = nullptr;
    static bool isFirstFrame = true;
    if (isFirstFrame && captureMode_ == SkiaCaptureMode::MultiFrame) {

    }
}

}