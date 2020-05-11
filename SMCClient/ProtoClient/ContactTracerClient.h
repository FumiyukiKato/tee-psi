#ifndef CONTACTTRACERCLIENT_H
#define CONTACTTRACERCLIENT_H

#include <thread>

#include <grpc/grpc.h>
#include <grpcpp/channel.h>
#include <grpcpp/client_context.h>
#include <grpcpp/create_channel.h>
#include <grpcpp/security/credentials.h>

#include "Messages.pb.h"
#include "Messages.grpc.pb.h"
#include "UtilityFunctions.h"

using namespace util;

using grpc::Channel;
using grpc::ClientContext;
using grpc::ClientReader;
using grpc::ClientReaderWriter;
using grpc::ClientWriter;
using grpc::Status;
using Messages::ContactTracer;

class ContactTracerClient {
    public:
        ContactTracerClient(std::shared_ptr<Channel> channel);
        void JudgeContact();

    private:
        std::unique_ptr<ContactTracer::Stub> stub_;
};

#endif