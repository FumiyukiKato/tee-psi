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
#include "NetworkManagerServer.h"
#include "Messages.pb.h"
#include "UtilityFunctions.h"
#include "remote_attestation_result.h"
//#include "LogBase.h"
#include "../GeneralSettings.h"
#include "EnclaveService.h"

using namespace std;
using namespace util;

class PsiService {

public:
    PsiService();
    virtual ~PsiService();
    void handleVerification(Messages::MessageMsg0 &msg, EnclaveService *enclave_service);
    int handleMsg0(Messages::MessageMsg0 &msg0, Messages::MessageMSG1 &msg1, EnclaveService *enclave_service);

private:
    int generateMSG1(Messages::MessageMSG1 &msg, EnclaveService *enclave_service);

};

#endif
