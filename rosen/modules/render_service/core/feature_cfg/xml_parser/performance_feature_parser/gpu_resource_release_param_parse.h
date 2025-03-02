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

#ifndef GPU_RESOURCE_RELEASE_PARAM_PARSE_H
#define GPU_RESOURCE_RELEASE_PARAM_PARSE_H

#include "xml_parser_base.h"
#include "gpu_resource_release_param.h"

namespace OHOS::Rosen {
class DeeplyRelGpuResParamParse : public XMLParserBase {
public:
    DeeplyRelGpuResParamParse() = default;
    ~DeeplyRelGpuResParamParse() = default;

    int32_t ParseFeatureParam(FeatureParamMapType &featureMap, xmlNode &node) override;

private:
    int32_t ParseDeeplyRelGpuResInternal(FeatureParamMapType &featureMap, xmlNode &node);
    std::shared_ptr<DeeplyRelGpuResParam> deeplyRelGpuResParam_;
};
} // namespace OHOS::Rosen
#endif // GPU_RESOURCE_RELEASE_PARAM_PARSE_H