Package: cuda:x64-windows@10.1#13

**Host Environment**

- Host: x64-windows
- Compiler: MSVC 19.41.34120.0
-    vcpkg-tool version: 2024-06-10-02590c430e4ed9215d27870138c2e579cc338772
    vcpkg-readonly: true
    vcpkg-scripts version: 6f1ddd6b6878e7e66fcc35c65ba1d8feec2e01f8

**To Reproduce**

`vcpkg install `

**Failure logs**

```
-- Executing NVCC-NOTFOUND --version resulted in error: 1
CMake Error at C:/Users/ricar/AppData/Local/vcpkg/registries/git-trees/d7709c275f8ce58e6d1b4c71b8d37fba4a9a0377/vcpkg_find_cuda.cmake:69 (message):
  Could not find CUDA.  Before continuing, please download and install CUDA
  (v10.1.0 or higher) from:

      https://developer.nvidia.com/cuda-downloads

Call Stack (most recent call first):
  C:/Users/ricar/AppData/Local/vcpkg/registries/git-trees/d7709c275f8ce58e6d1b4c71b8d37fba4a9a0377/portfile.cmake:9 (vcpkg_find_cuda)
  scripts/ports.cmake:175 (include)



```

**Additional context**

<details><summary>vcpkg.json</summary>

```
{
  "dependencies": [
    "boost-asio",
    "cuda",
    "fmt"
  ]
}

```
</details>
