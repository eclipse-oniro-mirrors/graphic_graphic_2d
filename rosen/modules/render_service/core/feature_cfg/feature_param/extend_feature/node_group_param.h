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

#ifndef NODE_GROUP_PARAM_H
#define NODE_GROUP_PARAM_H

#include "feature_param.h"

namespace OHOS::Rosen {
class NodeGroupParam : public FeatureParam {
public:
    NodeGroupParam() = default;
    ~NodeGroupParam() = default;

    bool IsGroupByUIEnabled() const;

protected:
    void SetGroupByUIEnabled(bool enabled);

private:
    bool groupByUIEnabled_ = false;

    friend class NodeGroupParamParse;
};
} // namespace OHOS::Rosen
#endif // NODE_GROUP_PARAM_H