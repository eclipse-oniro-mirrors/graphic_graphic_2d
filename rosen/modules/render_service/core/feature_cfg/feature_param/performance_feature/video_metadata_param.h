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

#ifndef VIDEO_METADATA_PARAM_H
#define VIDEO_METADATA_PARAM_H

#include <unordered_map>

#include "feature_param.h"

namespace OHOS::Rosen {
class VideoMetadataParam : public FeatureParam {
public:
    VideoMetadataParam() = default;
    ~VideoMetadataParam() = default;

    static const std::unordered_map<std::string, std::string>& GetVideoMetadataAppMap();

protected:
    static void AddVideoMetadataApp(const std::string& appName, const std::string& val);

private:
    inline static std::unordered_map<std::string, std::string> videoMetadataAppMap_{};

    friend class VideoMetadataParamParse;
};
} // namespace OHOS::Rosen
#endif // VIDEO_METADATA_PARAM_H