#ifndef CONTACTTRACER_H
#define CONTACTTRACER_H

#include <mutex>

#include "Messages.pb.h"
#include "Messages.grpc.pb.h"
#include "UtilityFunctions.h"

using namespace util;

using grpc::ServerContext;
using grpc::ServerReaderWriter;
using grpc::Status;

using Messages::ContactTracer;
using Messages::JudgeContactRequest;
using Messages::JudgeContactResponse;


class ContactTracerImpl final : public ContactTracer::Service {
    public:
        Status JudgeContact(ServerContext* context, ServerReaderWriter<JudgeContactResponse, JudgeContactRequest>* stream) override;
    private:
        
};

#endif