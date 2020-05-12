#include "PsiService.h"

using namespace util;

PsiService::PsiService() {}
PsiService::~PsiService() {}

void PsiService::handleVerification(Messages::MessageMsg0 &msg, EnclaveService *enclave_service) {
    Log("[gRPC] Verification request received");
    Log("[gRPC] Call MSG0 generate");
    uint32_t extended_epid_group_id = enclave_service->getExtendedEPID_GID();

    msg.set_type(RA_MSG0);
    msg.set_epid(extended_epid_group_id);
}

int PsiService::handleMsg0(Messages::MessageMsg0 &msg0, Messages::MessageMSG1 &msg1, EnclaveService *enclave_service) {
    Log("MSG0 response received");

    if (msg0.status() == TYPE_OK) {
        Log("Sending msg1 to remote attestation service provider. Expecting msg2 back");
        auto ret = this->generateMSG1(msg1, enclave_service);
        return ret;
    } else {
        Log("MSG0 response status was not OK", log::error);
    }

    return -1;
}

int PsiService::generateMSG1(Messages::MessageMSG1 &msg, EnclaveService *enclave_service) {
    int retGIDStatus = 0;
    int count = 0;
    sgx_status_t ret;
    sgx_ra_context_t context = INT_MAX;
    sgx_ra_msg1_t sgxMsg1Obj;
    
    ret = enclave_service->raInit(&context);
    if (SGX_SUCCESS != ret) {
        Log("Error, call enclave_init_ra fail", log::error);
        return -1;
    }

    while (1) {
        retGIDStatus = sgx_ra_get_msg1(context,
                                       enclave_service->getID(),
                                       sgx_ra_get_ga,
                                       &sgxMsg1Obj);

        if (retGIDStatus == SGX_SUCCESS) {
            break;
        } else if (retGIDStatus == SGX_ERROR_BUSY) {
            if (count == 5) { //retried 5 times, so fail out
                Log("Error, sgx_ra_get_msg1 is busy - 5 retries failed", log::error);
                break;;
            } else {
                sleep(3);
                count++;
            }
        } else {    //error other than busy
            Log("Error, failed to generate MSG1", log::error);
            break;
        }
    }

    if (SGX_SUCCESS == retGIDStatus) {
        Log("MSG1 generated Successfully");

        msg.set_type(RA_MSG1);
        msg.set_context(context);

        for (auto x : sgxMsg1Obj.g_a.gx)
            msg.add_gax(x);

        for (auto x : sgxMsg1Obj.g_a.gy)
            msg.add_gay(x);

        for (auto x : sgxMsg1Obj.gid) {
            msg.add_gid(x);
        }
        return 0;
    }

    return -1;
}