#ifndef ENCLAVESERVICE_H
#define ENCLAVESERVICE_H

#include "Messages.pb.h"
#include "Enclave.h"
#include "UtilityFunctions.h"

#define SALT_SIZE 32

using namespace std;
using namespace util;

class EnclaveService {

public:
    EnclaveService();
    virtual ~EnclaveService();
    int load(string data_file_path);
    uint32_t getExtendedEPID_GID();
    sgx_enclave_id_t getID();
    sgx_status_t raInit(sgx_ra_context_t *ra_context);
    void raClose(sgx_ra_context_t ra_context);


protected:
    Enclave *enclave = NULL;
};

#endif