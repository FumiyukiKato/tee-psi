#ifndef PSISERVICE_H
#define PSISERVICE_H

#include <string>
#include <stdio.h>
#include <limits.h>
#include <unistd.h>
#include <iostream>
#include <iomanip>
#include <vector>
#include <curl/curl.h>
#include <jsoncpp/json/json.h>
#include <numeric>

#include "Enclave.h"
#include "UtilityFunctions.h"
#include "../GeneralSettings.h"

#define SESSIONTOKEN_SIZE 32
#define SESSIONKEY_SIZE 16
#define SALT_SIZE 32
#define GCMTAG_SIZE 16
#define RECORD_SIZE 19

using namespace std;
using namespace util;

typedef struct HistoryData {
    vector<uint8_t *> geo_data_vec;
    vector<uint8_t *> gcm_tag_vec;
    vector<size_t> size_list_vec;
    size_t total_num() {
        return size_list_vec.size();
    }
    size_t total_geo_data_size() {
        return std::accumulate(size_list_vec.begin(), size_list_vec.end(), 0);
    }
    size_t total_gcm_tag_size() {
        return total_num() * GCMTAG_SIZE;
    }
    // 呼び出し側にメモリを確保してもらう
    void geo_data_as_array(uint8_t *mem) {
        uint32_t index = 0;
        for(int i=0; i<total_num(); i++) {
            memcpy(mem + index, geo_data_vec[i], size_list_vec[i]);
            index = index + size_list_vec[i];
        }
    }
    // 呼び出し側にメモリを確保してもらう
    void gcm_tag_as_array(uint8_t *mem) {
        uint32_t index = 0;
        for(int i=0; i<total_num(); i++) {
            memcpy(mem + index, gcm_tag_vec[i], GCMTAG_SIZE);
            index = index + GCMTAG_SIZE;
        }
    }
    // 呼び出し側にメモリを確保してもらう
    void size_list_as_array(size_t *mem, size_t size) {
        for (int i=0; i<size; i++) { 
            mem[i] = size_list_vec[i];
        }
    }
} HistoryData;

class PsiService {

public:
    PsiService();
    virtual ~PsiService();
    
    void start(string filepath);
    int remoteAttestationMock(uint8_t *token, uint8_t *sk);    
    int judgeContact(
        string user_id,
        uint8_t *session_token,
        uint8_t *encrypted_secret_key,
        uint8_t *secret_key_gcm_tag,
        uint8_t *risk_level,
        uint8_t *result_mac
    );
    int loadDataFromBlockChain(string user_id, HistoryData *encryptedGeoData);
    int loadAndStoreInfectedData(
        string user_id,
        uint8_t *session_token,
        uint8_t *encrypted_secret_key,
        uint8_t *secret_key_gcm_tag
);
    
private:
    sgx_status_t initEnclave();
    uint32_t getExtendedEPID_GID();

protected:
    Enclave *enclave = NULL;

};

#endif
