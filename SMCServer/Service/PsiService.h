#ifndef PSISERVICE_H
#define PSISERVICE_H

#include <string>
#include <stdio.h>
#include <limits.h>
#include <unistd.h>
#include <iostream>
#include <iomanip>
#include <vector>

#include "Enclave.h"
#include "UtilityFunctions.h"
#include "../GeneralSettings.h"

enum ClientMode {
    P2P,
    CENTRAL
};

#define KEY_SIZE 32

using namespace std;
using namespace util;

class PsiService {

public:
    PsiService();
    virtual ~PsiService();
    
    void start(string filepath);
    int remoteAttestationMock(uint8_t *token, uint8_t *sk);

private:
    sgx_status_t initEnclave();
    uint32_t getExtendedEPID_GID();
    int loadHashedData(const string file_path, string psi_salt);

protected:
    Enclave *enclave = NULL;

private:
    int busy_retry_time = 4;
    string data_path;
    std::vector<string> hash_vector;
    std::map<string, string> data_map;
    Clocker clocker;

};

#endif

