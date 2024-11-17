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

#include "pixelmapfromsurface_fuzzer.h"

#include <securec.h>

#include "pixel_map_from_surface.h"
#include "iconsumer_surface.h"
#include "surface_utils.h"
#include "transaction/rs_interfaces.h"
#include "common/rs_background_thread.h"
#include "core/pipeline/rs_render_engine.h"

namespace OHOS {
    using namespace Rosen;
    class BufferConsumerTestListener : public ::OHOS::IBufferConsumerListener {
    public:
        void OnBufferAvailable() override
        {
        }
    };
    namespace {
        const uint8_t* data_ = nullptr;
        size_t size_ = 0;
        size_t pos;
    }

    /*
    * describe: get data from outside untrusted data(data_) which size is according to sizeof(T)
    * tips: only support basic type
    */
    template<class T>
    T GetData()
    {
        T object {};
        size_t objectSize = sizeof(object);
        if (data_ == nullptr || objectSize > size_ - pos) {
            return object;
        }
        errno_t ret = memcpy_s(&object, objectSize, data_ + pos, objectSize);
        if (ret != EOK) {
            return {};
        }
        pos += objectSize;
        return object;
    }

#if defined(RS_ENABLE_UNI_RENDER) && defined(RS_ENABLE_GL)
    void PrepareSurfaceBuffer(int32_t width, int32_t height, sptr<IConsumerSurface> &cSurface, sptr<Surface> &pSurface)
    {
        cSurface = IConsumerSurface::Create();
        if (!cSurface) {
            return;
        }
        sptr<IBufferConsumerListener> listener = new BufferConsumerTestListener();
        cSurface->RegisterConsumerListener(listener);
        sptr<IBufferProducer> producer = cSurface->GetProducer();
        if (!producer) {
            return;
        }
        pSurface = Surface::CreateSurfaceAsProducer(producer);
        if (!pSurface) {
            return;
        }

        int releaseFence = -1;
        sptr<SurfaceBuffer> buffer = nullptr;
        BufferRequestConfig requestConfig = {
            .width = width,
            .height = height,
            .strideAlignment = 0x8,
            .format = GRAPHIC_PIXEL_FMT_RGBA_8888,
            .usage = BUFFER_USAGE_CPU_READ | BUFFER_USAGE_CPU_WRITE | BUFFER_USAGE_MEM_DMA,
            .timeout = 0,
        };
        BufferFlushConfig flushConfig = {
            .damage = {
                .w = width,
                .h = height,
            }
        };
        GSError ret = pSurface->RequestBuffer(buffer, releaseFence, requestConfig);
        if (ret != OHOS::GSERROR_OK) {
            return;
        }
        ret = pSurface->FlushBuffer(buffer, releaseFence, flushConfig);
        if (ret != OHOS::GSERROR_OK) {
            return;
        }
    }

    bool DoSomethingInterestingWithMyAPI(const uint8_t* data, size_t size)
    {
        if (data == nullptr) {
            return false;
        }

        // initialize
        data_ = data;
        size_ = size;
        pos = 0;

        int32_t width = 100;
        int32_t height = 100;
        sptr<IConsumerSurface> cSurface = nullptr;
        sptr<Surface> pSurface = nullptr;
        PrepareSurfaceBuffer(width, height, cSurface, pSurface);
        if (!pSurface) {
            return false;
        }
        std::shared_ptr<RSBaseRenderEngine> renderEngine = std::make_shared<RSRenderEngine>();
        renderEngine->Init();
        auto renderContext = renderEngine->GetRenderContext();
        if (!renderContext) {
            return false;
        }
        RSBackgroundThread::Instance().InitRenderContext(renderContext.get());

        OHOS::Media::Rect rect1 = {
            .left = GetData<uint32_t>() % width,
            .top = GetData<uint32_t>() % height,
            .width = GetData<uint32_t>() % width,
            .height = GetData<uint32_t>() % height,
        };
        OHOS::Media::Rect rect2 = {
            .left = GetData<uint32_t>(),
            .top = GetData<uint32_t>(),
            .width = GetData<uint32_t>(),
            .height = GetData<uint32_t>(),
        };
        (void)OHOS::Rosen::CreatePixelMapFromSurface(nullptr, rect1);
        (void)OHOS::Rosen::CreatePixelMapFromSurface(pSurface, rect1);
        (void)OHOS::Rosen::CreatePixelMapFromSurface(pSurface, rect2);
        return true;
    }
#endif
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
#if defined(RS_ENABLE_UNI_RENDER) && defined(RS_ENABLE_GL)
    OHOS::DoSomethingInterestingWithMyAPI(data, size);
#endif
    return 0;
}

