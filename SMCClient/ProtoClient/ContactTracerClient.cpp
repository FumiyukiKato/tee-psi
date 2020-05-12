#include "ContactTracerClient.h"

using namespace util;

using Messages::JudgeContactResponse;
using Messages::JudgeContactRequest;
using Messages::InitialMessage;
using Messages::MessageMsg0;
using grpc::ClientContext;
using grpc::ClientReaderWriter;

ContactTracerClient::ContactTracerClient(std::shared_ptr<Channel> channel, ClientMode mode)
    : stub_(ContactTracer::NewStub(channel)) {
    this->ws = WebService::getInstance();
    this->ws->init();
    this->sp = new PSIWorker(this->ws);
}

void ContactTracerClient::handleMSG0(MessageMsg0 *msg) {
    uint32_t extended_epid_group_id = msg->epid();
    int ret = this->sp->sp_ra_proc_msg0_req(extended_epid_group_id);

    if (ret == 0)
        msg->set_status(TYPE_OK);
    else
        msg->set_status(TYPE_TERMINATE);
}

ContactTracerClient::~ContactTracerClient() {}

void ContactTracerClient::JudgeContact() {
    ClientContext context;
    std::shared_ptr<ClientReaderWriter<JudgeContactRequest, JudgeContactResponse> > stream(
        stub_->JudgeContact(&context));

    JudgeContactResponse res;
    JudgeContactRequest req;
    
    // initial message
    InitialMessage msg;
    msg.set_type(RA_VERIFICATION);
    req.mutable_initial_message()->CopyFrom(msg);
    stream->Write(req);
    stream->WritesDone();
    Log("[gRPC] client RA_VERIFICATION");

    while (stream->Read(&res)) {
        switch (res.action_case()) {
            case JudgeContactResponse::ActionCase::kMsg0: {
                Log("[gRPC] Receive Message0");
                MessageMsg0 msg0 = res.msg0();
                this->handleMSG0(&msg0);
                req.mutable_msg0()->CopyFrom(msg0);
                stream->Write(req);
                stream->WritesDone();
                Log("[gRPC] client RA_MSG0");
                break;
            }

            case JudgeContactResponse::ActionCase::kMsg1: {
                Log("[gRPC] Receive Message1");
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
