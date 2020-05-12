#include "ContactTracer.h"
#include <unistd.h>

using namespace util;
using namespace std;

using grpc::Status;
using Messages::JudgeContactRequest;
using Messages::JudgeContactResponse;
using Messages::JudgeContactRequest;
using Messages::MessageMsg0;
using Messages::MessageMSG1;
using grpc::ServerContext;
using grpc::ServerReaderWriter;

std::mutex mu_;

ContactTracerImpl::ContactTracerImpl(string filepath) {
    this->data_path = filepath;
    Log("f");
    this->enclave_service = new EnclaveService();
    Log("e");
    this->psi_service = new PsiService();
    Log("p");
}

ContactTracerImpl::~ContactTracerImpl() {
    delete this->psi_service;
    delete this->enclave_service;
}

int ContactTracerImpl::initialize() {
    int status = this->enclave_service->load(this->data_path);
    if (status < 0) return -1;
    return 0;
}

Status ContactTracerImpl::JudgeContact(ServerContext* context,
                ServerReaderWriter<JudgeContactResponse, JudgeContactRequest>* stream) {
    JudgeContactRequest req;
    JudgeContactResponse res;
    while (stream->Read(&req)) {
        Log("[gRPC] loop");
        std::unique_lock<std::mutex> lock(mu_);
        switch (req.action_case()) {
            case JudgeContactRequest::ActionCase::kInitialMessage: {
                Log("[gRPC] Get InitialMessage");
                MessageMsg0 msg;
                this->psi_service->handleVerification(msg, this->enclave_service);
                res.mutable_msg0()->CopyFrom(msg);
                stream->Write(res);
                break;
            }

            case JudgeContactRequest::ActionCase::kMsg0: {
                Log("[gRPC] Get Message0");
                MessageMsg0 msg0 = res.msg0();
                MessageMSG1 msg1;
                this->psi_service->handleMsg0(msg0, msg1, this->enclave_service);
                res.mutable_msg1()->CopyFrom(msg1);
                stream->Write(res);
                break;
            }
            
            default: {
                break;
            }
        }
    }
    
    return Status::OK;
}

