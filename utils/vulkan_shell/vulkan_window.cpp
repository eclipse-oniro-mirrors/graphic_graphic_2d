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

#include "vulkan_window.h"

#include <memory>
#include <string>

#include "include/gpu/GrDirectContext.h"
#include "vulkan_application.h"
#include "vulkan_device.h"
#include "vulkan_hilog.h"
#include "vulkan_native_surface.h"
#include "vulkan_surface.h"
#include "vulkan_swapchain.h"

namespace OHOS::Rosen::vulkan {

static const int K_GR_CACHE_MAX_COUNT = 8192;
static const size_t K_GR_CACHE_MAX_BYTE_SIZE = 512 * (1 << 20);

RSVulkanProcTable* RSVulkanWindow::vk = nullptr;
std::unique_ptr<RSVulkanApplication> RSVulkanWindow::application_;
std::unique_ptr<RSVulkanDevice> RSVulkanWindow::logicalDevice_;
std::thread::id RSVulkanWindow::deviceThread_;
std::vector<RSVulkanHandle<VkFence>> RSVulkanWindow::sharedFences_;
uint32_t RSVulkanWindow::sharedFenceIndex_ = false;
bool RSVulkanWindow::presenting_ = false;

void RSVulkanWindow::InitializeVulkan(size_t threadNum)
{
    if (sharedFences_.size() < threadNum) {
        sharedFences_.resize(threadNum);
        sharedFenceIndex_ = 0;
    }

    if (logicalDevice_ != nullptr) {
        LOGI("Vulkan Already Initialized");
        return;
    }

    LOGI("First Initialize Vulkan");
    deviceThread_ = std::this_thread::get_id();

    vk = new RSVulkanProcTable();
    if (!vk->HasAcquiredMandatoryProcAddresses()) {
        LOGE("Proc table has not acquired mandatory proc addresses.");
        return;
    }

    // Create the application instance.
    std::vector<std::string> extensions = {
        VK_KHR_SURFACE_EXTENSION_NAME, // parent extension
        VK_OHOS_SURFACE_EXTENSION_NAME // child extension
    };

    application_ = std::make_unique<RSVulkanApplication>(*vk, "Rosen", std::move(extensions));
    if (!application_->IsValid() || !vk->AreInstanceProcsSetup()) {
        // Make certain the application instance was created and it setup the
        // instance proc table entries.
        LOGE("Instance proc addresses have not been setup.");
        return;
    }

    // Create the device.
    logicalDevice_ = application_->AcquireFirstCompatibleLogicalDevice();
    if (logicalDevice_ == nullptr || !logicalDevice_->IsValid() || !vk->AreDeviceProcsSetup()) {
        // Make certain the device was created and it setup the device proc table
        // entries.
        LOGE("Device proc addresses have not been setup.");
        return;
    }
}

RSVulkanWindow::RSVulkanWindow(std::unique_ptr<RSVulkanNativeSurface> nativeSurface, bool isOffscreen)
    : valid_(false), isOffscreen_(isOffscreen)
{
    LOGE("VulkanWindow init enter");

    InitializeVulkan();
    if (logicalDevice_ == nullptr) {
        LOGE("InitializeVulkan failed");
        return;
    }

    if (!isOffscreen && (nativeSurface == nullptr || !nativeSurface->IsValid())) {
        LOGE("Native surface is invalid.");
        return;
    }

    // Create the logical surface from the native platform surface.
    if (!isOffscreen) {
        surface_ = std::make_unique<RSVulkanSurface>(*vk, *application_, std::move(nativeSurface));
        if (!surface_->IsValid()) {
            LOGE("Vulkan surface is invalid.");
            return;
        }
    }

    // Create the Skia GrContext.
    if (!CreateSkiaGrContext()) {
        LOGE("Could not create Skia context.");
        return;
    }

    // Create the swapchain.
    if (!isOffscreen && !RecreateSwapchain()) {
        LOGE("Could not setup the swapchain initially.");
        return;
    }
    LOGE("VulkanWindow init success");
    valid_ = true;
}

RSVulkanWindow::~RSVulkanWindow() = default;

bool RSVulkanWindow::IsValid() const
{
    return valid_;
}

GrDirectContext* RSVulkanWindow::GetSkiaGrContext()
{
    return skiaGrContext_.get();
}

GrVkBackendContext& RSVulkanWindow::GetSkiaBackendContext()
{
    return skBackendContext_;
}

bool RSVulkanWindow::CreateSkiaGrContext()
{
    if (!CreateSkiaBackendContext(&skBackendContext_)) {
        LOGE("CreateSkiaGrContext CreateSkiaBackendContext is false");
        return false;
    }

    sk_sp<GrDirectContext> context = GrDirectContext::MakeVulkan(skBackendContext_);

    if (context == nullptr) {
        LOGE("CreateSkiaGrContext context is null");
        return false;
    }

    context->setResourceCacheLimits(K_GR_CACHE_MAX_COUNT, K_GR_CACHE_MAX_BYTE_SIZE);

    skiaGrContext_ = context;

    return true;
}

bool RSVulkanWindow::CreateSkiaBackendContext(GrVkBackendContext* context)
{
    auto getProc = vk->CreateSkiaGetProc();
    if (getProc == nullptr) {
        LOGE("CreateSkiaBackendContext getProc is null");
        return false;
    }

    uint32_t skiaFeatures = 0;
    if (!logicalDevice_->GetPhysicalDeviceFeaturesSkia(&skiaFeatures)) {
        LOGE("CreateSkiaBackendContext GetPhysicalDeviceFeaturesSkia is false");
        return false;
    }

    context->fInstance = application_->GetInstance();
    context->fPhysicalDevice = logicalDevice_->GetPhysicalDeviceHandle();
    context->fDevice = logicalDevice_->GetHandle();
    context->fQueue = logicalDevice_->GetQueueHandle();
    context->fGraphicsQueueIndex = logicalDevice_->GetGraphicsQueueIndex();
    context->fMinAPIVersion = application_->GetAPIVersion();
    uint32_t extensionFlags = kKHR_surface_GrVkExtensionFlag;
    if (!isOffscreen_) {
        extensionFlags |= kKHR_swapchain_GrVkExtensionFlag;
        extensionFlags |= surface_->GetNativeSurface().GetSkiaExtensionName();
    }
    context->fExtensions = extensionFlags;

    context->fFeatures = skiaFeatures;
    context->fGetProc = std::move(getProc);
    context->fOwnsInstanceAndDevice = false;
    return true;
}

sk_sp<SkSurface> RSVulkanWindow::AcquireSurface(int bufferCount)
{
    if (isOffscreen_ || !IsValid()) {
        LOGE("Surface is invalid or offscreen.");
        return nullptr;
    }

    auto surface_size = surface_->GetSize();
    if (surface_size != SkISize::Make(0, 0) && surface_size != swapchain_->GetSize()) {
        LOGE("Swapchain and surface sizes are out of sync. Recreating swapchain.");
        if (!RecreateSwapchain()) {
            LOGE("Could not recreate swapchain.");
            valid_ = false;
            return nullptr;
        }
    }

    while (true) {
        sk_sp<SkSurface> surface;
        auto acquireResult = RSVulkanSwapchain::AcquireStatus::ERROR_SURFACE_LOST;

        std::tie(acquireResult, surface) = swapchain_->AcquireSurface(bufferCount);

        if (acquireResult == RSVulkanSwapchain::AcquireStatus::SUCCESS) {
            // Successfully acquired a surface from the swapchain. Nothing more to do.
            return surface;
        }

        if (acquireResult == RSVulkanSwapchain::AcquireStatus::ERROR_SURFACE_LOST) {
            // Surface is lost. This is an unrecoverable error.
            LOGE("Swapchain reported surface was lost.");
            return nullptr;
        }

        if (acquireResult == RSVulkanSwapchain::AcquireStatus::ERROR_SURFACE_OUT_OF_DATE) {
            LOGE("AcquireSurface surface out of date");
            if (RecreateSwapchain()) {
                continue;
            } else {
                LOGE("Swapchain reported surface was out of date but "
                     "could not recreate the swapchain at the new "
                     "configuration.");
                valid_ = false;
                return nullptr;
            }
        }

        break;
    }

    LOGE("Unhandled VulkanSwapchain::AcquireResult");
    return nullptr;
}

bool RSVulkanWindow::SwapBuffers()
{
    if (isOffscreen_ || !IsValid()) {
        LOGE("Window was invalid or offscreen.");
        return false;
    }
    if (deviceThread_ != std::this_thread::get_id()) {
        LOGI("MT mode in VulkanWindow::SwapBuffers()");
        swapchain_->AddToPresent();
        return swapchain_->FlushCommands();
    }
    LOGI("ST mode in VulkanWindow::SwapBuffers()");
    return swapchain_->Submit();
}

void RSVulkanWindow::PresentAll()
{
    //-----------------------------------------
    // create shared fences if not already
    //-----------------------------------------
    if (!sharedFences_[sharedFenceIndex_]) {
        const VkFenceCreateInfo create_info = {
            .sType = VK_STRUCTURE_TYPE_FENCE_CREATE_INFO,
            .pNext = nullptr,
            .flags = VK_FENCE_CREATE_SIGNALED_BIT,
        };

        auto fenceCollect = [](VkFence fence) {
            RSVulkanWindow::vk->DestroyFence(RSVulkanWindow::logicalDevice_->GetHandle(), fence, nullptr);
        };

        VkFence fence = VK_NULL_HANDLE;

        if (VK_CALL_LOG_ERROR(vk->CreateFence(logicalDevice_->GetHandle(), &create_info, nullptr, &fence)) !=
            VK_SUCCESS) {
            return;
        }
        sharedFences_[sharedFenceIndex_] = { fence, fenceCollect };
    }
    RSVulkanSwapchain::PresentAll(sharedFences_[sharedFenceIndex_]);
    sharedFenceIndex_++;
    if (sharedFenceIndex_ >= sharedFences_.size()) {
        sharedFenceIndex_ = 0;
    }
    presenting_ = true;
}

bool RSVulkanWindow::WaitForSharedFence()
{
    if (presenting_) {
        if (sharedFences_[sharedFenceIndex_]) {
            VkFence fence = sharedFences_[sharedFenceIndex_];
            return VK_CALL_LOG_ERROR(vk->WaitForFences(logicalDevice_->GetHandle(), 1, &fence, true,
                std::numeric_limits<uint64_t>::max())) == VK_SUCCESS;
        }
    }
    return false;
}

bool RSVulkanWindow::ResetSharedFence()
{
    if (presenting_) {
        presenting_ = false;
        if (sharedFences_[sharedFenceIndex_]) {
            VkFence fence = sharedFences_[sharedFenceIndex_];
            return VK_CALL_LOG_ERROR(vk->ResetFences(logicalDevice_->GetHandle(), 1, &fence)) == VK_SUCCESS;
        }
    }
    return false;
}

VkDevice RSVulkanWindow::GetDevice()
{
    return logicalDevice_->GetHandle();
}

VkPhysicalDevice RSVulkanWindow::GetPhysicalDevice()
{
    return logicalDevice_->GetPhysicalDeviceHandle();
}

RSVulkanProcTable& RSVulkanWindow::GetVkProcTable()
{
    return *vk;
}

bool RSVulkanWindow::RecreateSwapchain()
{
    if (isOffscreen_) {
        LOGE("offscreen vulkan window, don't need swapchian");
        return false;
    }
    // This way, we always lose our reference to the old swapchain. Even if we
    // cannot create a new one to replace it.
    auto old_swapchain = std::move(swapchain_);

    if (!vk->IsValid()) {
        LOGE("RecreateSwapchain vk not valid");
        return false;
    }

    if (logicalDevice_ == nullptr || !logicalDevice_->IsValid()) {
        LOGE("RecreateSwapchain logicalDevice_ not valid");
        return false;
    }

    if (surface_ == nullptr || !surface_->IsValid()) {
        LOGE("RecreateSwapchain surface_ not valid");
        return false;
    }

    if (skiaGrContext_ == nullptr) {
        LOGE("RecreateSwapchain skiaGrContext_ not valid");
        return false;
    }

    auto swapchain = std::make_unique<RSVulkanSwapchain>(*vk, *logicalDevice_, *surface_, skiaGrContext_.get(),
        std::move(old_swapchain), logicalDevice_->GetGraphicsQueueIndex());
    if (!swapchain->IsValid()) {
        LOGE("RecreateSwapchain swapchain not valid");
        return false;
    }

    swapchain_ = std::move(swapchain);
    return true;
}

} // namespace OHOS::Rosen::vulkan
