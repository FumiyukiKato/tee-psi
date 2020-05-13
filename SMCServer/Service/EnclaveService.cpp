#include "EnclaveService.h"
#include "sample_libcrypto.h"
#include "sha256.h"

using namespace std;

EnclaveService::EnclaveService() {
    this->enclave = Enclave::getInstance();
    sgx_status_t ret = this->enclave->createEnclave();
    if (SGX_SUCCESS != ret) {
        Log("Error, call initEnclave fail", log::error);
        return;
    }
}

EnclaveService::~EnclaveService() {
    delete this->enclave;
}

int EnclaveService::load(string data_file_path) {
    sgx_status_t status;
    uint8_t salt[SALT_SIZE];
    std::vector<string> hash_vector;
    //read file
    uint8_t * file_data = NULL;
    int file_size = 0;

    sgx_status_t ret = initialize(this->enclave->getID(), &status, salt);
    if ((SGX_SUCCESS != ret) || (SGX_SUCCESS != status)) {
        Log("Error, call generate_salt fail", log::error);
        return -1;
    }

    // saltでハッシュ化してenclave内にロードする
    string psi_salt = ByteArrayToString(salt, SALT_SIZE);
    Log("[PSI] load central data from : %s", data_file_path);

    file_size = ReadFileToBuffer(data_file_path, &file_data);
    if (file_size <= 0) {
        return -1;
    }

    char * p = (char*)file_data;
    const char * s = p;
    char* n = (char*)p;
    for( ; p - s < file_size; p = n + 1) {
        n = strchr(p, '\n');
        if (n == NULL) {
            n = p + strlen(p);
        } else {
            n[0] = '\0';
        }
        if (strlen(p) <= 0) {
            continue;
        }

        sgx_sha256_hash_t report_data = {0};
        Sha256 sha256;
        sha256.update((uint8_t*)p, strlen(p));
        sha256.update((uint8_t*)psi_salt.c_str(), psi_salt.size());
        sha256.hash((sgx_sha256_hash_t * )&report_data);

        string hash = ByteArrayToString(report_data, sizeof(sgx_sha256_hash_t));

        hash_vector.push_back(hash);
    }

    Log("[PSI] complete load and hash central data, size: %d", hash_vector.size());
    std::sort(hash_vector.begin(), hash_vector.end());
    int data_size = hash_vector.size();

    if (data_size < 0) {
        Log("Error, loading central data from file failed");
        return -1;
    }

    int hash_data_size = data_size * SAMPLE_SHA256_HASH_SIZE;
    uint8_t *hash_array = new uint8_t[hash_data_size];
    for (int i = 0; i < data_size; i++) {
        uint8_t * arr = NULL;
        int size = HexStringToByteArray(hash_vector[i], &arr);
        if (size != sizeof(sgx_sha256_hash_t)) {
            Log("[PSI] Get hash vector , something error: %d, %d, %s", size, sizeof(sgx_sha256_hash_t), hash_vector[i]);
            return -1;
        }
        memcpy(hash_array + i*sizeof(sgx_sha256_hash_t), arr, size);
    }

    ret = uploadCentralData(this->enclave->getID(), &status, hash_array, hash_data_size);
    delete[] hash_array;
    if ((SGX_SUCCESS != ret) || (SGX_SUCCESS != status)) {
        Log("[Error] uploadCentralData failed, %d, %d", ret, status);
        Log("Error, loading central data into sgx fail", log::error);
        return -1;
    }
    
    Log("[PSI] load done");
    return 0;
}

uint32_t EnclaveService::getExtendedEPID_GID() {
    uint32_t extended_epid_group_id = 0;
    int ret = sgx_get_extended_epid_group_id(&extended_epid_group_id);

    if (SGX_SUCCESS != ret) {
        ret = -1;
        Log("Error, call sgx_get_extended_epid_group_id fail");
        return ret;
    }

    Log("Call sgx_get_extended_epid_group_id success");

    return extended_epid_group_id;
}

sgx_enclave_id_t EnclaveService::getID() {
    return this->enclave->getID();
}

sgx_status_t EnclaveService::raInit(sgx_ra_context_t *ra_context) {
    return this->enclave->raInit(ra_context);
}

void EnclaveService::raClose(sgx_ra_context_t ra_context) {
    return this->enclave->raClose(ra_context);
}