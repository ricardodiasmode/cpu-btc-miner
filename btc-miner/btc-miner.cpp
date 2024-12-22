#include <iostream>
#include <string>
#include <boost/asio.hpp>
#include <cstdint>
#include <iomanip>
#include <sstream>
#include <nlohmann/json.hpp>
#include <openssl/evp.h>  // For OpenSSL 3.0
#include <regex>

static constexpr uint8_t SUBSCRIBE_MESSAGE_ID = 1;
static constexpr uint8_t AUTHORIZE_MESSAGE_ID = 2;
static constexpr uint8_t SUBMIT_MESSAGE_ID = 3;
static constexpr char ACCOUNT_NAME[] = "RicardoRocky01";
static constexpr char ACCOUNT_PASSWORD[] = "123456";
static constexpr char WORKER_NAME[] = "RicardoRocky01.001";
static constexpr char POOL_URL[] = "bs.poolbinance.com";

static constexpr bool DEBUG_WORK_DATA = false;
static constexpr bool DEBUG_MINING = false;
static constexpr bool DEBUG_HASH_RATE = true;

// Definições gerais
using namespace std;
namespace asio = boost::asio;
using json = nlohmann::json;

std::string IntToHex(uint64_t value, size_t width = 8) {
    std::ostringstream stream;
    stream << std::hex << std::setfill('0') << std::setw(width) << value;
    return stream.str();
}

std::string StringToHex(const std::string& data) {
    std::ostringstream oss;
    for (unsigned char c : data) {
        oss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(c);
    }
    return oss.str();
}

// Utility: Converts an integer to a hex string (little-endian by default)
std::string Int32ToHex(uint32_t value, bool littleEndian = true) {
    std::ostringstream oss;
    if (littleEndian) {
        for (int i = 0; i < 4; ++i) {
            oss << std::hex << std::setw(2) << std::setfill('0') << (value & 0xFF);
            value >>= 8;
        }
    }
    else {
        oss << std::hex << std::setw(8) << std::setfill('0') << value;
    }
    return oss.str();
}

uint64_t stringToUint64(const std::string& hexString) {
    if (hexString.size() < 16) {
        throw std::invalid_argument("Hex string too short for uint64_t conversion.");
    }
    // Extract the first 16 characters of the hash
    std::string first16 = hexString.substr(0, 16);

    // Convert the first 16 characters to uint64_t
    uint64_t value = 0;
    std::istringstream iss(first16);
    iss >> std::hex >> value;

    if (iss.fail()) {
        throw std::invalid_argument("Invalid hex string for uint64_t conversion.");
    }

    return value;
}

std::string VecInt8ToHex(const std::vector<uint8_t>& bytes) {
    std::ostringstream oss;
    for (uint8_t byte : bytes) {
        oss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(byte);
    }
    return oss.str();
}

void AppendLittleEndian(std::vector<uint8_t>& vec, uint32_t value) {
    for (int i = 0; i < 4; ++i) {
        vec.push_back((value >> (i * 8)) & 0xFF);
    }
}

std::vector<uint8_t> HexStringToBytes(const std::string& hexStr) {
    if (hexStr.size() % 2 != 0) {
        throw std::invalid_argument("Hex string must have an even length");
    }

    std::vector<uint8_t> bytes(hexStr.size() / 2);
    for (size_t i = 0; i < bytes.size(); ++i) {
        bytes[i] = static_cast<uint8_t>(std::stoi(hexStr.substr(i * 2, 2), nullptr, 16));
    }
    return bytes;
}

std::string sha256d(const std::string& data) {
    // Use RAII to ensure EVP context is cleaned up
    struct EVP_MD_CTX_Deleter {
        void operator()(EVP_MD_CTX* ctx) const { EVP_MD_CTX_free(ctx); }
    };
    std::unique_ptr<EVP_MD_CTX, EVP_MD_CTX_Deleter> ctx(EVP_MD_CTX_new());
    if (!ctx) {
        throw std::runtime_error("Failed to create EVP_MD_CTX");
    }

    // First SHA-256 pass
    unsigned char first_hash[EVP_MAX_MD_SIZE];
    unsigned int first_hash_len = 0;
    if (EVP_DigestInit_ex(ctx.get(), EVP_sha256(), nullptr) != 1 ||
        EVP_DigestUpdate(ctx.get(), data.data(), data.size()) != 1 ||
        EVP_DigestFinal_ex(ctx.get(), first_hash, &first_hash_len) != 1) {
        throw std::runtime_error("SHA-256 hashing failed in the first pass");
    }

    // Second SHA-256 pass
    unsigned char second_hash[EVP_MAX_MD_SIZE];
    unsigned int second_hash_len = 0;
    if (EVP_DigestInit_ex(ctx.get(), EVP_sha256(), nullptr) != 1 ||
        EVP_DigestUpdate(ctx.get(), first_hash, first_hash_len) != 1 ||
        EVP_DigestFinal_ex(ctx.get(), second_hash, &second_hash_len) != 1) {
        throw std::runtime_error("SHA-256 hashing failed in the second pass");
    }

    // Return as a hex string
    return StringToHex(std::string(reinterpret_cast<char*>(second_hash), second_hash_len));
}

struct work_data
{
    std::string job_id;
    std::string prev_block_hash;
    std::string generation_tx_part1;
    std::string generation_tx_part2;
    std::vector<std::string> merkle_branches;
    uint32_t block_version;
    uint32_t nBits;
    uint32_t nTime;
    bool clean_jobs;
    uint64_t difficulty;
    std::string ExtraNonce1;
    uint32_t ExtraNonce2;
    uint32_t ExtraNonceSize2;

    std::string remainder_data = "";

    std::string constructCoinbase() {
        return generation_tx_part1 + ExtraNonce1 + Int32ToHex(ExtraNonce2) + generation_tx_part2;
    }

    // Calculate the Merkle root
    std::string calculateMerkleRoot() {
        std::string hash = sha256d(constructCoinbase()); // Double SHA-256 of the coinbase

        // Iterate through the branches
        for (const auto& branch : merkle_branches) {
            if (branch.size() != 64 || !std::all_of(branch.begin(), branch.end(), ::isxdigit)) {
                throw std::invalid_argument("Invalid branch: must be a 64-character hexadecimal string");
            }

            // Combine hashes (big-endian ordering assumed for concatenation)
            std::string branch_bytes = StringToHex(branch);
            hash = sha256d(hash + branch_bytes);
        }

        return hash; // Final Merkle root
    }

    std::string SerializeHeader(uint32_t version, const std::string& previousHash, const std::string& merkleRoot,
        uint32_t nTime, uint32_t bits, uint32_t nonce) {
        // Validate input sizes
        if (previousHash.size() != 64 || !std::all_of(previousHash.begin(), previousHash.end(), ::isxdigit)) {
            throw std::invalid_argument("Invalid previous hash: must be a 64-character hexadecimal string");
        }
        if (merkleRoot.size() != 64 || !std::all_of(merkleRoot.begin(), merkleRoot.end(), ::isxdigit)) {
            throw std::invalid_argument("Invalid Merkle root: must be a 64-character hexadecimal string");
        }

        // Convert fields to bytes
        std::vector<uint8_t> headerBytes;
        headerBytes.reserve(80); // Bitcoin block headers are always 80 bytes

        // Append version (little-endian)
        AppendLittleEndian(headerBytes, version);

        // Append previous block hash (big-endian)
        auto prevHashBytes = HexStringToBytes(previousHash);
        headerBytes.insert(headerBytes.end(), prevHashBytes.rbegin(), prevHashBytes.rend()); // Reverse for big-endian

        // Append Merkle root (big-endian)
        auto merkleRootBytes = HexStringToBytes(merkleRoot);
        headerBytes.insert(headerBytes.end(), merkleRootBytes.rbegin(), merkleRootBytes.rend()); // Reverse for big-endian

        // Append nTime (little-endian)
        AppendLittleEndian(headerBytes, nTime);

        // Append bits (little-endian)
        AppendLittleEndian(headerBytes, bits);

        // Append nonce (little-endian)
        AppendLittleEndian(headerBytes, nonce);

        // Return the header as a hex string
        return VecInt8ToHex(headerBytes);
    }

    std::string GetHeader(uint32_t nonce) 
    {
        return SerializeHeader(block_version, prev_block_hash, calculateMerkleRoot(), nTime, nBits, nonce);
    }

    std::string AppendExtraNonce() {
        return ExtraNonce1 + IntToHex(ExtraNonce2);
    }

    work_data() = default;
};

static void send_request(asio::ip::tcp::socket& socket, const json& request) {
    std::string message = request.dump() + "\n";
    boost::asio::write(socket, boost::asio::buffer(message));
    std::cout << "Sent: " << message;
}

class Miner
{
    asio::ip::tcp::socket MinerSocket;
    work_data received_data;

public:

    bool isValidExtraNonce2(std::string extraNonce2) {
        return extraNonce2.size() <= size_t(4) * 2; // Each byte is 2 hex characters
    }

    Miner(asio::io_context& io_context) : MinerSocket(io_context)
    {
        try {
            boost::asio::ip::tcp::resolver resolver(io_context);
            auto endpoints = resolver.resolve(POOL_URL, "3333");
            boost::asio::connect(MinerSocket, endpoints);
            std::cout << "Connection successful on URL: " << POOL_URL << std::endl;
        }
        catch (const boost::system::system_error& e) {
            std::cerr << "Connection failed: " << e.what() << std::endl;
        }
    }

    ~Miner()
    {
        try {
            MinerSocket.close();
        }
        catch (const boost::system::system_error& e) {
            std::cerr << "Error closing socket: " << e.what() << '\n';
        }
    }

    void Subscribe()
    {
        json subscribe_request = {
            {"id", SUBSCRIBE_MESSAGE_ID},
            {"method", "mining.subscribe"},
            {"params", {WORKER_NAME}}
        };
        send_request(MinerSocket, subscribe_request);
    }

    void Authenticate()
    {
        json auth_request = {
            {"id", AUTHORIZE_MESSAGE_ID},
            {"method", "mining.authorize"},
            {"params", {ACCOUNT_NAME, ACCOUNT_PASSWORD}}
        };
        send_request(MinerSocket, auth_request);
    }

    void SendSolution(const uint32_t& nonce)
    {
        if (!isValidExtraNonce2(IntToHex(received_data.ExtraNonce2)))
        {
            cerr << "Submitted ExtraNonce2 is not valid. Request will probably fail." << endl;
        }

        json solution_request = {
                    {"id", SUBMIT_MESSAGE_ID},
                    {"method", "mining.submit"},
                    {"params", {WORKER_NAME, received_data.job_id, IntToHex(received_data.ExtraNonce2), received_data.nTime, Int32ToHex(nonce)}}
        };
        send_request(MinerSocket, solution_request);
    }

    void ParseExtraNoncesResponse(json j) {
        // Extra nonce message like: {"error":null,"id":1,"result":[[["mining.notify","0000473d1"],["mining.set_difficulty","0000473d2"]],"0000473d",8]}
        cout << "Parsing extra nonces..." << endl;
        received_data.ExtraNonce1 = j["result"][1];
        received_data.ExtraNonceSize2 = j["result"][2];
    }

    bool VerifyAuthorizeResponse(json j) {
        // Subscribe response message like: {"error":null,"id":2,"result":true}
        cout << "Verifying authorization..." << endl;
        if (!j["error"].is_null())
        {
            cerr << "Error on parse subscribe: " << j["error"] << endl;
            return false;
        }
        if (!j["result"])
        {
            cerr << "Error on parse subscribe: " << "result is false." << endl;
            return false;
        }
        cout << "Miner authorized." << endl;
        return true;
    }

    void ParseWorkData(json j) {
        if (DEBUG_WORK_DATA)
            cout << "Working with data: " << j << endl;

        // Getting data
        received_data.job_id = j["params"][0].get<std::string>();
        received_data.prev_block_hash = j["params"][1].get<std::string>();
        received_data.generation_tx_part1 = j["params"][2].get<std::string>();
        received_data.generation_tx_part2 = j["params"][3].get<std::string>();

        // Parse merkle branches
        for (const auto& branch : j["params"][4]) {
            received_data.merkle_branches.push_back(branch.get<std::string>());
        }

        // Parse other parameters
        received_data.block_version = std::stoul(j["params"][5].get<std::string>(), nullptr, 16); // Convert hex to uint32_t
        received_data.nBits = std::stoul(j["params"][6].get<std::string>(), nullptr, 16); // Convert hex to uint32_t
        received_data.nTime = std::stoul(j["params"][7].get<std::string>(), nullptr, 16); // Convert hex to uint32_t
        received_data.clean_jobs = j["params"][8].get<bool>();

        if (!received_data.job_id.empty()) {
            cout << "Received job_id: " << received_data.job_id << endl << endl;
        }
    }

    void ParseDifficultyData(json j) {
        received_data.difficulty = j["params"][0].get<uint64_t>();
    }

    bool ReceiveWorkData()
    {
        cout << "Receiving work data..." << endl;

        std::vector<char> buffer(2048);
        std::string accumulated_data = received_data.remainder_data;

        if (DEBUG_WORK_DATA)
            cout << "Last work data: " << accumulated_data << endl << endl;

        try {
            // Read data into the buffer
            size_t bytes_read = asio::read(MinerSocket, asio::buffer(buffer.data(), buffer.size()));

            // Ensure some data was read
            if (bytes_read == 0) {
                cerr << "No data received from miner socket." << endl;
                return false;
            }

            // Convert buffer to a string and append to accumulated data
            std::string work_data(buffer.data(), bytes_read);
            accumulated_data += work_data;

            if (DEBUG_WORK_DATA)
                cout << "Server response: " << accumulated_data << endl << endl;

            received_data.remainder_data = "";

            std::string line;
            std::stringstream ss(accumulated_data);
            while (std::getline(ss, line, '}')) {

                // Check if json_chunk is not empty and looks like a valid JSON object
                if (line.empty() || line == "null") {
                    return false;  // Skip invalid or empty chunks
                }

                try {
                    // Try parsing the current JSON chunk
                    json j = json::parse(line + '}');

                    if (j.contains("method"))
                    {
                        if (j["method"] == "mining.set_difficulty")
                        {
                            ParseDifficultyData(j);
                        }
                        else if (j["method"] == "mining.notify")
                        {
                            ParseWorkData(j);
                        }
                        else {
                            cout << "Could not understand data: " << line << endl;
                        }
                    }
                    else if (j.contains("error") && j["error"].is_null())
                    {
                        switch (j["id"].get<uint8_t>())
                        {
                        case SUBSCRIBE_MESSAGE_ID:
                            ParseExtraNoncesResponse(j);
                            break;
                        case AUTHORIZE_MESSAGE_ID:
                            if (!VerifyAuthorizeResponse(j))
                                return false;
                            break;
                        case SUBMIT_MESSAGE_ID:
                            cout << "Error on submitting response: " << j["error"][1] << endl << endl;
                            break;
                        default:
                            throw "Unexpected message id.";
                            break;
                        }
                    }
                    else if (j.contains("error") && !j["error"].is_null())
                    {
                        cout << "Remainder data parsed. We have an error: " << j["error"][1] << endl;
                        cout << "The error was given by message id: " << j["id"] << endl;

                        if (j["id"] == SUBMIT_MESSAGE_ID)
                            cout << "Means that our submit was ignored." << endl;

                        cout << endl;
                    }
                    else {
                        cout << "Could not understand data: " << line << endl;
                    }
                }
                catch (const std::exception& e) {
                    if (line.find("mining.notify") != std::string::npos)
                    {
                        if (DEBUG_WORK_DATA)
                            cout << "Parse remainder found. We are good to go: " << line << endl << endl;
                    }
                    received_data.remainder_data = line;

                    if (DEBUG_WORK_DATA)
                        cout << "Request remainder data: " << received_data.remainder_data << endl << endl;
                }
            }
        }
        catch (const std::exception& e) {
            cerr << "Error during work data reception: " << e.what() << endl;
            return false;
        }
    }

    uint64_t calculateTarget(uint64_t difficulty) {
        uint64_t maxTarget = 0xFFFF000000000000; // High 64 bits of the full maximum target
        return maxTarget / difficulty;
    }

    void Mine(uint64_t target) {
        uint32_t nonce = 0;

        uint64_t nHashes = 0;

        std::chrono::time_point<std::chrono::system_clock> StartTime = std::chrono::system_clock::now();

        while (true) {
            std::string blockHeader = received_data.GetHeader(nonce);

            if (DEBUG_MINING)
                cout << "Block header: " << blockHeader << endl;

            // Compute the double SHA-256 hash of the block header
            std::string hashHex = sha256d(blockHeader);
            nHashes++;

            // If did one billion hashes, print time
            if (DEBUG_HASH_RATE && 
                nHashes % 10000 == 0)
            {
                std::chrono::time_point<std::chrono::system_clock> Now = std::chrono::system_clock::now();

                const auto DeltaTime = std::chrono::duration_cast<chrono::seconds>(Now - StartTime).count();

                cout << "Made " << nHashes << " hashes in " << DeltaTime << " seconds.";
            }

            if (DEBUG_MINING)
                cout << "Hash (hex): " << hashHex << endl;

            // Convert hashHex to a numeric value for comparison
            uint64_t hashValue = stringToUint64(hashHex.substr(0, 16)); // Only consider the first 64 bits for comparison

            if (DEBUG_MINING)
                cout << "Hash value (numeric): " << hashValue << endl;

            // Verify if the hash meets the target
            if (hashValue <= target) {

                cout << "Nonce found: " << nonce << endl;
                cout << "Hash: " << hashValue << endl;
                cout << "target: " << target << endl;

                SendSolution(nonce);
                break; // Break the loop once a valid solution is found
            }

            // Increment ExtraNonce2 and reset if it exceeds the limit
            received_data.ExtraNonce2++;
            if (received_data.ExtraNonce2 > received_data.ExtraNonceSize2) {
                received_data.ExtraNonce2 = 0;
            }

            nonce++;
        }
    }

    void StartMiner() {
        while (true) {
            if (!ReceiveWorkData()) {
                cout << "Miner failed to receive work data." << endl << endl;
                break;
            }

            // Calculate the target based on the difficulty
            uint64_t target = calculateTarget(received_data.difficulty);

            cout << "--- Starting POW. ---" << endl;
            Mine(target);
            cout << "--- POW finished. ---" << endl << endl;
        }
    }
};

int main() {
    try {
        cout << "Initializing miner..." << endl << endl;
        asio::io_context io_context;
        Miner CurrentMiner(io_context);
        
        cout << "Miner initialized. Subscribing..." << endl << endl;
        CurrentMiner.Subscribe();

        cout << "Miner subscribed. Authenticating..." << endl << endl;
        CurrentMiner.Authenticate();

        cout << "Miner authenticated, start mining..." << endl << endl;
        CurrentMiner.StartMiner();
    }
    catch (std::exception& e) {
        cerr << "Error: " << e.what() << endl;
        return 1;
    }

    return 0;
}
