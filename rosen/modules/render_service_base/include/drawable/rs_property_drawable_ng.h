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

#ifndef RENDER_SERVICE_BASE_DRAWABLE_RS_PROPERTY_DRAWABLE_H
#define RENDER_SERVICE_BASE_DRAWABLE_RS_PROPERTY_DRAWABLE_H

#include <memory>

#include "drawable/rs_drawable.h"

namespace OHOS::Rosen {
class RSPropertyDrawCmdList;

class RSPropertyDrawableNG : RSDrawable {
public:
    RSPropertyDrawableNG() = default;
    ~RSPropertyDrawableNG() override = default;

    void Draw(RSPaintFilterCanvas& canvas) const override;

protected:
    std::shared_ptr<RSPropertyDrawCmdList> cmdList_;
};

} // namespace OHOS::Rosen
#endif // RENDER_SERVICE_BASE_DRAWABLE_RS_PROPERTY_DRAWABLE_H