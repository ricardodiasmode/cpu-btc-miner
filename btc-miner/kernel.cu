#include <stdint.h>
#include <device_launch_parameters.h>

// Kernel de mineração para GPUs
__device__ void sha256_double(const uint8_t* header, uint32_t nonce, uint8_t* hash) {
    for (int i = 0; i < 32; ++i) {
        hash[i] = header[i % 80] ^ (nonce >> (i % 8));
    }
}

__global__ void StartMiner(uint8_t* header, uint32_t start_nonce, uint32_t* result, uint32_t target) {
    uint32_t idx = blockIdx.x * blockDim.x + threadIdx.x + start_nonce;
    uint8_t hash[32];

    sha256_double(header, idx, hash);

    if (hash[0] == 0 && hash[1] == 0 && hash[2] < target) {
        *result = idx;
    }
}
