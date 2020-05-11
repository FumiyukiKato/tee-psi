#include "ContactTracerClient.h"

using namespace util;

using Messages::JudgeContactRequest;
using Messages::JudgeContactResponse;
using Messages::JudgeContactRequest;
using Messages::InitialMessage;
using Messages::MessageMsg0;
using grpc::ClientContext;
using grpc::ClientReaderWriter;

ContactTracerClient::ContactTracerClient(std::shared_ptr<Channel> channel)
    : stub_(ContactTracer::NewStub(channel)) {}

void ContactTracerClient::JudgeContact() {
    ClientContext context;

    std::shared_ptr<ClientReaderWriter<JudgeContactRequest, JudgeContactResponse> > stream(
        stub_->JudgeContact(&context));

    JudgeContactResponse res;    

    JudgeContactRequest req;
    InitialMessage msg;
    msg.set_type(4);
    msg.set_size(200);
    std::cout << "Sending message " << msg.type() << std::endl;
    req.mutable_initial_message()->CopyFrom(msg);
    stream->Write(req);
    stream->WritesDone();
    Log("[gRPC] Write done");


    Log("[gRPC] start read");
    while (stream->Read(&res)) {
        Log("[gRPC] Get message");
        switch (res.action_case()) {
            case JudgeContactResponse::ActionCase::kMsg0: {
                Log("[gRPC] Get Message0");
                MessageMsg0 msg = res.msg0();
                std::cout << "type is " << msg.type() << std::endl;
                break;
            }
            
            default: {
                break;
            }
        }
    }
    
    Status status = stream->Finish();

    if (!status.ok()) {
         std::cout << "rpc failed" << std::endl;
    } else {
        std::cout << "ok" << std::endl;
    }
}