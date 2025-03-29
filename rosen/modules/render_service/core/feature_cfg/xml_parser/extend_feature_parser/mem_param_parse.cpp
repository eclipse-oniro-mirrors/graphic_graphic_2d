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

#include <sstream>
#include "mem_param_parse.h"

namespace OHOS::Rosen {

int32_t MEMParamParse::ParseFeatureParam(FeatureParamMapType &featureMap, xmlNode &node)
{
    RS_LOGI("MEMParamParse start");
    xmlNode *currNode = &node;
    if (currNode == nullptr || currNode->xmlChildrenNode == nullptr) {
        RS_LOGD("MEMParamParse stop parsing, no nodes");
        return PARSE_GET_CHILD_FAIL;
    }

    currNode = currNode->xmlChildrenNode;
    for (; currNode; currNode = currNode->next) {
        if (currNode->type != XML_ELEMENT_NODE) {
            continue;
        }

        if (ParseMemInternal(featureMap, *currNode) != PARSE_EXEC_SUCCESS) {
            RS_LOGD("MEMParamParse stop parsing, parse internal fail");
            return PARSE_INTERNAL_FAIL;
        }
    }

    return PARSE_EXEC_SUCCESS;
}

int32_t MEMParamParse::ParseMemInternal(FeatureParamMapType &featureMap, xmlNode &node)
{
    xmlNode *currNode = &node;

    auto iter = featureMap.find(FEATURE_CONFIGS[MEM]);
    if (iter != featureMap.end()) {
        memParam_ = std::static_pointer_cast<MEMParam>(iter->second);
    } else {
        RS_LOGD("MEMParamParse stop parsing, no initializing param map");
        return PARSE_NO_PARAM;
    }

    // Start Parse Feature Params
    int xmlParamType = GetXmlNodeAsInt(*currNode);
    auto name = ExtractPropertyValue("name", *currNode);
    auto val = ExtractPropertyValue("value", *currNode);
    if (xmlParamType == PARSE_XML_FEATURE_SINGLEPARAM) {
        if (name == "RsWatchPoint") {
            memParam_->SetRSWatchPoint(val);
            RS_LOGI("MEMParamParse parse RSWatchPoint %{public}s", memParam_->GetRSWatchPoint().c_str());
        } else if (name == "RSCacheLimitsResourceSize") {
            int num;
            std::istringstream iss(val);
            if (iss >> num) {
                memParam_->SetRSCacheLimitsResourceSize(num);
                RS_LOGI("RSCacheLimitsResourceSize %{public}d", memParam_->GetRSCacheLimitsResourceSize());
            } else {
                RS_LOGE("MEMParamParse parse RSCacheLimitsResourceSize Fail.");
            }
        }
    } else if (xmlParamType == PARSE_XML_FEATURE_SWITCH) {
        if (name == "ReclaimEnabled") {
            bool isEnabled = ParseFeatureSwitch(val);
            memParam_->SetReclaimEnabled(isEnabled);
            RS_LOGI("MEMParamParse parse ReclaimEnabled %{public}d", memParam_->IsReclaimEnabled());
        }
    }

    return PARSE_EXEC_SUCCESS;
}
} // namespace OHOS::Rosen