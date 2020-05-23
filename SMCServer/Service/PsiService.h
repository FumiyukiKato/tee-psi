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

#include "Enclave.h"
#include "UtilityFunctions.h"
#include "../GeneralSettings.h"

#define SESSIONTOKEN_SIZE 32
#define SESSIONKEY_SIZE 16
#define SALT_SIZE 32

using namespace std;
using namespace util;

typedef struct GeoData {
    uint8_t *data;
    uint8_t *gcm_tag;
} GeoData;

typedef struct HistoryData {
    vector<GeoData> encrypted_data;
    size_t data_num;
    size_t max_data_size;
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
        uint8_t *secret_key,
        uint8_t *gcm_tag,
        uint8_t *risk_level,
        uint8_t *result_mac
    );
    int loadDataFromBlockChain(string user_id, HistoryData *encryptedGeoData);
    int loadAndStoreInfectedData(string user_id, uint8_t *session_token, uint8_t *secret_key, uint8_t *gcm_tag);
    
private:
    sgx_status_t initEnclave();
    uint32_t getExtendedEPID_GID();

protected:
    Enclave *enclave = NULL;

};

#endif
