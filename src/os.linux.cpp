#include "os.hpp"
#include "string.hpp"
#include <limits>
#include <fstream>
#include <link.h>
#include <dlfcn.h>

[[nodiscard]] std::vector<std::string> os_get_command_line() noexcept
{
    std::ifstream file("/proc/self/cmdline", std::ios::binary);
    if (!file)
    {
        return {};
    }

    // Move to the end of the file.
    file.unsetf(std::ios::skipws);
    file.ignore(std::numeric_limits<std::streamsize>::max());

    auto size = file.gcount();
    if (size == 0)
    {
        return {};
    }

    // Clear flags and move back to the beginning of the file.
    file.clear();
    file.seekg(0, std::ios::beg);

    // Read in the file.
    std::vector<u8> buf{};
    buf.resize(size);

    if (!file.read((char *)buf.data(), size))
    {
        return {};
    }

    // Adjust size for any null terminators so it splits nicely.
    while (size > 0 && buf[size - 1] == '\0')
    {
        --size;
    }

    return str_split({(cstr)buf.data(), (usize)size}, '\0');
}

[[nodiscard]] u8 *os_get_module(std::string_view module_name) noexcept
{
    auto *handle = dlopen(module_name.empty() ? nullptr : module_name.data(), RTLD_NOW | RTLD_NOLOAD);
    if (handle == nullptr)
    {
        return nullptr;
    }

    dlclose(handle);

    return (u8 *)handle;
}

[[nodiscard]] u8 *os_get_module(u8 *address) noexcept
{
    if (address == nullptr)
    {
        return nullptr;
    }

    Dl_info info;
    if (dladdr(address, &info) == 0 || info.dli_fname == nullptr)
    {
        return nullptr;
    }

    return os_get_module(info.dli_fname);
}

[[nodiscard]] u8 *os_get_module_base(u8 *handle) noexcept
{
    if (handle == nullptr)
    {
        return nullptr;
    }

    link_map link;
    if (dlinfo(handle, RTLD_DI_LINKMAP, &link) != 0)
    {
        return nullptr;
    }

    return (u8 *)link.l_addr;
}

[[nodiscard]] u8 *os_get_procedure(u8 *handle, std::string_view proc_name) noexcept
{
    if (handle == nullptr || proc_name.empty())
    {
        return nullptr;
    }

    return (u8 *)dlsym(handle, proc_name.data());
}
