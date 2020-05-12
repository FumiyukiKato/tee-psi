// Generated by the gRPC C++ plugin.
// If you make any local change, they will be lost.
// source: Messages.proto

#include "Messages.pb.h"
#include "Messages.grpc.pb.h"

#include <functional>
#include <grpcpp/impl/codegen/async_stream.h>
#include <grpcpp/impl/codegen/async_unary_call.h>
#include <grpcpp/impl/codegen/channel_interface.h>
#include <grpcpp/impl/codegen/client_unary_call.h>
#include <grpcpp/impl/codegen/client_callback.h>
#include <grpcpp/impl/codegen/message_allocator.h>
#include <grpcpp/impl/codegen/method_handler.h>
#include <grpcpp/impl/codegen/rpc_service_method.h>
#include <grpcpp/impl/codegen/server_callback.h>
#include <grpcpp/impl/codegen/server_callback_handlers.h>
#include <grpcpp/impl/codegen/server_context.h>
#include <grpcpp/impl/codegen/service_type.h>
#include <grpcpp/impl/codegen/sync_stream.h>
namespace Messages {

static const char* ContactTracer_method_names[] = {
  "/Messages.ContactTracer/JudgeContact",
};

std::unique_ptr< ContactTracer::Stub> ContactTracer::NewStub(const std::shared_ptr< ::grpc::ChannelInterface>& channel, const ::grpc::StubOptions& options) {
  (void)options;
  std::unique_ptr< ContactTracer::Stub> stub(new ContactTracer::Stub(channel));
  return stub;
}

ContactTracer::Stub::Stub(const std::shared_ptr< ::grpc::ChannelInterface>& channel)
  : channel_(channel), rpcmethod_JudgeContact_(ContactTracer_method_names[0], ::grpc::internal::RpcMethod::BIDI_STREAMING, channel)
  {}

::grpc::ClientReaderWriter< ::Messages::JudgeContactRequest, ::Messages::JudgeContactResponse>* ContactTracer::Stub::JudgeContactRaw(::grpc::ClientContext* context) {
  return ::grpc_impl::internal::ClientReaderWriterFactory< ::Messages::JudgeContactRequest, ::Messages::JudgeContactResponse>::Create(channel_.get(), rpcmethod_JudgeContact_, context);
}

void ContactTracer::Stub::experimental_async::JudgeContact(::grpc::ClientContext* context, ::grpc::experimental::ClientBidiReactor< ::Messages::JudgeContactRequest,::Messages::JudgeContactResponse>* reactor) {
  ::grpc_impl::internal::ClientCallbackReaderWriterFactory< ::Messages::JudgeContactRequest,::Messages::JudgeContactResponse>::Create(stub_->channel_.get(), stub_->rpcmethod_JudgeContact_, context, reactor);
}

::grpc::ClientAsyncReaderWriter< ::Messages::JudgeContactRequest, ::Messages::JudgeContactResponse>* ContactTracer::Stub::AsyncJudgeContactRaw(::grpc::ClientContext* context, ::grpc::CompletionQueue* cq, void* tag) {
  return ::grpc_impl::internal::ClientAsyncReaderWriterFactory< ::Messages::JudgeContactRequest, ::Messages::JudgeContactResponse>::Create(channel_.get(), cq, rpcmethod_JudgeContact_, context, true, tag);
}

::grpc::ClientAsyncReaderWriter< ::Messages::JudgeContactRequest, ::Messages::JudgeContactResponse>* ContactTracer::Stub::PrepareAsyncJudgeContactRaw(::grpc::ClientContext* context, ::grpc::CompletionQueue* cq) {
  return ::grpc_impl::internal::ClientAsyncReaderWriterFactory< ::Messages::JudgeContactRequest, ::Messages::JudgeContactResponse>::Create(channel_.get(), cq, rpcmethod_JudgeContact_, context, false, nullptr);
}

ContactTracer::Service::Service() {
  AddMethod(new ::grpc::internal::RpcServiceMethod(
      ContactTracer_method_names[0],
      ::grpc::internal::RpcMethod::BIDI_STREAMING,
      new ::grpc::internal::BidiStreamingHandler< ContactTracer::Service, ::Messages::JudgeContactRequest, ::Messages::JudgeContactResponse>(
          std::mem_fn(&ContactTracer::Service::JudgeContact), this)));
}

ContactTracer::Service::~Service() {
}

::grpc::Status ContactTracer::Service::JudgeContact(::grpc::ServerContext* context, ::grpc::ServerReaderWriter< ::Messages::JudgeContactResponse, ::Messages::JudgeContactRequest>* stream) {
  (void) context;
  (void) stream;
  return ::grpc::Status(::grpc::StatusCode::UNIMPLEMENTED, "");
}


}  // namespace Messages
