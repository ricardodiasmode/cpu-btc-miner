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
static constexpr bool DEBUG_WORK_DATA = false;

// Definições gerais
using namespace std;
namespace asio = boost::asio;
using json = nlohmann::json;

std::vector<uint8_t> Int32ToByte(int32_t value) {
    std::vector<uint8_t> bytes(4);
    bytes[0] = (value >> 24) & 0xFF;
    bytes[1] = (value >> 16) & 0xFF;
    bytes[2] = (value >> 8) & 0xFF;
    bytes[3] = value & 0xFF;
    return bytes;
}

std::vector<uint8_t> StringToByte(const std::string& str) {
    return std::vector<uint8_t>(str.begin(), str.end());
}

std::vector<uint8_t> VectorStringToByte(const std::vector<std::string>& strings) {
    std::vector<uint8_t> bytes;
    for (const auto& str : strings) {
        std::vector<uint8_t> strBytes = StringToByte(str);
        bytes.insert(bytes.end(), strBytes.begin(), strBytes.end());
    }
    return bytes;
}

std::string toHex(uint32_t value, int width = 8) {
    std::stringstream stream;
    stream << std::hex << std::setw(width) << std::setfill('0') << value;
    return stream.str();
}

std::vector<uint8_t> sha256(const std::vector<uint8_t>& data) {
    // Create a new EVP context for SHA256
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (ctx == nullptr) {
        throw std::runtime_error("Failed to create EVP context");
    }

    // Initialize the SHA256 context
    if (EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr) != 1) {
        EVP_MD_CTX_free(ctx);
        throw std::runtime_error("Failed to initialize SHA256 context");
    }

    // Update the context with the data
    if (EVP_DigestUpdate(ctx, data.data(), data.size()) != 1) {
        EVP_MD_CTX_free(ctx);
        throw std::runtime_error("Failed to update SHA256 context");
    }

    // Prepare the output buffer
    std::vector<uint8_t> hash(EVP_MD_size(EVP_sha256()));

    // Finalize the digest and get the result
    if (EVP_DigestFinal_ex(ctx, hash.data(), nullptr) != 1) {
        EVP_MD_CTX_free(ctx);
        throw std::runtime_error("Failed to finalize SHA256 context");
    }

    // Free the context
    EVP_MD_CTX_free(ctx);

    return hash;
}

// Function to perform a double SHA-256 hash
std::vector<uint8_t> doubleSha256(const std::vector<uint8_t>& data) {
    return sha256(sha256(data));
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
    uint64_t ExtraNonce1;
    uint32_t ExtraNonce2;
    uint32_t ExtraNonceSize2;

    std::string remainder_data = "";

    std::vector<uint8_t> GetHeader()
    {
        std::vector<uint8_t> BlockVersionToVector = Int32ToByte(block_version);
        std::vector<uint8_t> PreviousBlockToVector = StringToByte(prev_block_hash);
        std::vector<uint8_t> MerkleBranchesToVector = VectorStringToByte(merkle_branches);
        std::vector<uint8_t> TimestampToVector = Int32ToByte(nTime);
        std::vector<uint8_t> BitsToVector = Int32ToByte(nBits);

        std::vector<uint8_t> Header;
        Header.insert(Header.end(), BlockVersionToVector.begin(), BlockVersionToVector.end());
        Header.insert(Header.end(), PreviousBlockToVector.begin(), PreviousBlockToVector.end());
        Header.insert(Header.end(), MerkleBranchesToVector.begin(), MerkleBranchesToVector.end());
        Header.insert(Header.end(), TimestampToVector.begin(), TimestampToVector.end());
        Header.insert(Header.end(), BitsToVector.begin(), BitsToVector.end());
        return Header;
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

    // Converter string de hash para um valor numérico
    uint64_t HashToTarget(const string& hash) {
        return stoull(hash.substr(0, 16), nullptr, 16);
    }

    Miner(asio::io_context& io_context) : MinerSocket(io_context)
    {
        try {
            boost::asio::ip::tcp::resolver resolver(io_context);
            auto endpoints = resolver.resolve("sha256.poolbinance.com", "3333");
            boost::asio::connect(MinerSocket, endpoints);
            std::cout << "Connection successful!" << std::endl;
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
            {"params", {"RicardoRocky01.001"}}
        };
        send_request(MinerSocket, subscribe_request);
    }

    void Authenticate()
    {
        json auth_request = {
            {"id", AUTHORIZE_MESSAGE_ID},
            {"method", "mining.authorize"},
            {"params", {"RicardoRocky01", "123456"}}
        };
        send_request(MinerSocket, auth_request);
    }

    void SendSolution(const uint32_t& nonce)
    {
        json solution_request = {
                    {"id", SUBMIT_MESSAGE_ID},
                    {"method", "mining.submit"},
                    {"params", {"RicardoRocky01.001", received_data.job_id, toHex(received_data.ExtraNonce2), received_data.nTime, nonce}}
        };
        send_request(MinerSocket, solution_request);
    }

    void ParseExtraNoncesResponse(json j) {
        // Extra nonce message like: {"error":null,"id":1,"result":[[["mining.notify","0000473d1"],["mining.set_difficulty","0000473d2"]],"0000473d",8]}
        cout << "Parsing extra nonces..." << endl;
        std::string ExtraNonce1 = j["result"][1];
        received_data.ExtraNonce1 = std::stoull(ExtraNonce1);
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
        cout << "Receiving work data..." << endl << endl;

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

        while (true) {
            std::vector<uint8_t> blockHeader = received_data.GetHeader();
            std::vector<uint8_t> NonceAsVector = Int32ToByte(nonce);
            blockHeader.insert(blockHeader.end(), NonceAsVector.begin(), NonceAsVector.end());

            // Perform the double SHA-256
            std::vector<uint8_t> result = doubleSha256(blockHeader);

            // Convert the first 8 bytes of the hash to uint64_t
            uint64_t hashValue = 0;
            for (int i = 0; i < 8; i++) {
                hashValue = (hashValue << 8) | result[i];
            }

            // Verify if the hash meets the target
            if (hashValue <= target) {
                cout << "Nonce found: " << nonce << endl;
                cout << "Hash: " << hashValue << endl;

                SendSolution(nonce);
                break; // Break the loop once a valid solution is found
            }

            received_data.ExtraNonce2++;

            // Reset ExtraNonce2 if it exceeds the limit
            if (received_data.ExtraNonce2 > received_data.ExtraNonceSize2) {
                received_data.ExtraNonce2 = 0;
            }

            nonce++;
        }
    }

    void StartMiner() {
        while (true) {
            if (!ReceiveWorkData()) {
                cout << "Miner failed to receive work data. Trying again..." << endl << endl;
                continue;
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
        cerr << "Erro: " << e.what() << endl;
        return 1;
    }

    return 0;
}
