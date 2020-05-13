#ifndef CONTACTTRACER_H
#define CONTACTTRACER_H

#include <mutex>

#include "Enclave.h"
#include "Messages.pb.h"
#include "Messages.grpc.pb.h"
#include "UtilityFunctions.h"
#include "PsiService.h"
#include "EnclaveService.h"

using namespace util;
using namespace std;

using grpc::ServerContext;
using grpc::ServerReaderWriter;
using grpc::Status;

using Messages::ContactTracer;
using Messages::JudgeContactRequest;
using Messages::JudgeContactResponse;


class ContactTracerImpl final : public ContactTracer::Service {
    public:
        ContactTracerImpl(string filepath);
        virtual ~ContactTracerImpl();
        Status JudgeContact(ServerContext* context, ServerReaderWriter<JudgeContactResponse, JudgeContactRequest>* stream) override;
        int initialize();

    protected:
        Enclave *enclave = NULL;

    private:
        PsiService *psi_service;
        EnclaveService *enclave_service;
        std::string data_path;
};

#endif
