#include "PsiService.h"
#include "sample_libcrypto.h"
#include "sha256.h"

PsiService::PsiService() {
    Clocker clocker = Clocker("Total Request clocker");
    this->clocker = clocker;
}

PsiService::~PsiService() {
    delete this->enclave;
}


void PsiService::start(string path) {
    Log("[Service] enclave init");
    this->data_path = path;

    sgx_status_t ret = this->initEnclave();
    if (SGX_SUCCESS != ret) {
        Log("Error, call initEnclave fail", log::error);
        return;
    }

    sgx_status_t status;
    uint8_t salt[SALT_SIZE];
    ret = initialize(this->enclave->getID(), &status, salt);
    
    if ((SGX_SUCCESS != ret) || (SGX_SUCCESS != status)) {
        Log("Error, call generate_salt fail", log::error);
        return;
    }
    
    Clocker clocker = Clocker("Loading central data");
    clocker.start();

    // saltでハッシュ化してenclave内にロードする
    const string data_file_path = this->data_path;
    string psi_salt = ByteArrayToString(salt, SALT_SIZE);
    int data_size = loadHashedData(data_file_path, psi_salt);
    if (data_size < 0) {
        Log("Error, loading central data from file failed");
        return;
    }
    
    int hash_data_size = data_size * SAMPLE_SHA256_HASH_SIZE;
    uint8_t *hash_array = new uint8_t[hash_data_size];
    for (int i = 0; i < data_size; i++) {
        uint8_t * arr = NULL;
        int size = HexStringToByteArray(this->hash_vector[i], &arr);
        if (size != sizeof(sgx_sha256_hash_t)) {
            Log("[PSI] Get hash vector , something error: %d, %d, %s", size, sizeof(sgx_sha256_hash_t), this->hash_vector[i]);
            return;
        }
        memcpy(hash_array + i*sizeof(sgx_sha256_hash_t), arr, size);
    }
    clocker.stop();
    Log("end");
    
    clocker = Clocker("Uploading to enclave");
    clocker.start();    
    
    ret = uploadCentralData(this->enclave->getID(), &status, hash_array, hash_data_size);
    delete[] hash_array;
    if ((SGX_SUCCESS != ret) || (SGX_SUCCESS != status)) {
        Log("[Error] uploadCentralData failed, %d, %d", ret, status);
        Log("Error, loading central data into sgx fail", log::error);
        return;
    }
    clocker.stop();
    Log("[Service] Call initEnclave success");
}

int PsiService::loadHashedData(
    const string file_path,
    string psi_salt
) {
    //read file
    uint8_t * file_data = NULL;
    int file_size = 0;
    
    Log("[Service] load central data from : %s", this->data_path);

    file_size = ReadFileToBuffer(file_path, &file_data);
    if (file_size <= 0) {
        return -1;
    }
    
    char * p = (char*)file_data;
    const char * s = p;
    char* n = (char*)p;
    for( ; p - s < file_size; p = n + 1) {
        n = strchr(p, '\n');
        if (n == NULL) {
            //only one line or last line
            n = p + strlen(p);
        } else {
            n[0] = '\0';
        }
        if (strlen(p) <= 0) {//ignore null line
            continue;
        }

        sgx_sha256_hash_t report_data = {0};
        Sha256 sha256;
        sha256.update((uint8_t*)p, strlen(p));
        sha256.update((uint8_t*)psi_salt.c_str(), psi_salt.size());
        sha256.hash((sgx_sha256_hash_t * )&report_data);

        string hash = ByteArrayToString(report_data, sizeof(sgx_sha256_hash_t));

        this->hash_vector.push_back(hash);
        this->data_map[hash] = p;
    }
    Log("[Service] complete load and hash central data, size: %d", this->hash_vector.size());
    
    std::sort(this->hash_vector.begin(), this->hash_vector.end());
    return this->hash_vector.size();
}

sgx_status_t PsiService::initEnclave() {
    this->enclave = Enclave::getInstance();
    return this->enclave->createEnclave();
}

uint32_t PsiService::getExtendedEPID_GID() {
    uint32_t extended_epid_group_id = 0;
    int ret = sgx_get_extended_epid_group_id(&extended_epid_group_id);

    if (SGX_SUCCESS != ret) {
        ret = -1;
        Log("Error, call sgx_get_extended_epid_group_id fail");
        return ret;
    }

    return extended_epid_group_id;
}

int PsiService::remoteAttestationMock(uint8_t *token, uint8_t *sk) {
    Log("[Service] Remote Attestaion Mock start");
    sgx_status_t status;
    int ret = remote_attestation_mock(this->enclave->getID(), &status, token, sk);
    if ((SGX_SUCCESS != ret) || (SGX_SUCCESS != status)) {
        ret = -1;
        Log("Error, call remote_attestation_mock fail");
        return ret;
    }
    
    return 0;
}

int PsiService::judgeContact(
    uint8_t *session_token, 
    uint8_t *gcm_tag, 
    uint8_t *encrypted_history_data, 
    size_t array_size,
    uint8_t *risk_level,
    uint8_t *result,
    size_t history_num
) {
    Log("[Service] judge contact start");
    sgx_status_t status;
    sgx_status_t ret = judge_contact(
        this->enclave->getID(),
        &status,
        session_token,
        gcm_tag,
        encrypted_history_data,
        array_size,
        risk_level,
        result,
        history_num
    );
    if (SGX_SUCCESS != ret || SGX_SUCCESS != status) {
        Log("[Service] judge contact failed, %d, %d!", ret, status);
        return -1;
    }
    return 0;
}