#include "ContactTracer.h"
#include <unistd.h>

using namespace util;
using namespace std;
using grpc::Status;
using Messages::JudgeContactRequest;
using Messages::JudgeContactResponse;
using Messages::JudgeContactRequest;
using Messages::MessageMsg0;
using grpc::ServerContext;
using grpc::ServerReaderWriter;

std::mutex mu_;

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
                Log("type is %d", req.initial_message().type());
                MessageMsg0 msg;
                msg.set_type(3);
                msg.set_epid(100);
                msg.set_status(1);
                Log("erro is %d", 1);
                res.mutable_msg0()->CopyFrom(msg);
                Log("erro is %d", 3);
                stream->Write(res);
                Log("erro is %d", 4);
                break;
            }
            
            default: {
                break;
            }
        }
    }
    
    Log("erro is %d", 5);
    
    return Status::OK;
}

