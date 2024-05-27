/*
 * Copyright (C) 2024 Huawei Device Co., Ltd.
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
#ifndef UIEFFECT_FILTER_H
#define UIEFFECT_FILTER_H

#include "filter_para.h"

namespace OHOS {
namespace Rosen {
class Filter final {
public:
    Filter() = default;
    ~Filter() = default;

    void AddPara(const std::shared_ptr<FilterPara>& para)
    {
        filterParas_.emplace_back(para);
    }

    const std::vector<std::shared_ptr<FilterPara>>& GetAllPara() const
    {
        return filterParas_;
    }
private:
    std::vector<std::shared_ptr<FilterPara>> filterParas_;
};
} // namespace Rosen
} // namespace OHOS
#endif // UIEFFECT_FILTER_H
