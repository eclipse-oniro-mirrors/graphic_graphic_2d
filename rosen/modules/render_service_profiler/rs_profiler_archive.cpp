#include "rs_profiler_archive.h"

namespace OHOS::Rosen {

void Archive::Serialize(float& value)
{
    Serialize(&value, sizeof(value));
}

void Archive::Serialize(double& value)
{
    Serialize(&value, sizeof(value));
}

void Archive::Serialize(int32_t& value)
{
    Serialize(&value, sizeof(value));
}

void Archive::Serialize(uint32_t& value)
{
    Serialize(&value, sizeof(value));
}

void Archive::Serialize(size_t& value)
{
    Serialize(&value, sizeof(value));
}

void Archive::Serialize(std::string& value)
{
    size_t size = value.size();
    Serialize(size);

    if (IsReading())
        value.resize(size);

    Serialize(const_cast<char*>(value.data()), size);
}

} // namespace OHOS::Rosen