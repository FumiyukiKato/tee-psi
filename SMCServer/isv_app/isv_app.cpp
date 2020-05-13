// Licensed to the Apache Software Foundation (ASF) under one
// or more contributor license agreements.  See the NOTICE file
// distributed with this work for additional information
// regarding copyright ownership.  The ASF licenses this file
// to you under the Apache License, Version 2.0 (the
// "License"); you may not use this file except in compliance
// with the License.  You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License..

#include <iostream>
#include <unistd.h>

// #include "MessageHandler.h"
#include "ContactTracer.h"
#include "LogBase.h"
#include <grpc/grpc.h>
#include <grpc++/server.h>
#include <grpc++/server_builder.h>
#include <grpc++/server_context.h>
#include <grpc++/security/server_credentials.h>

using namespace util;


void RunServer(char *filepath) {
    string server_address("0.0.0.0:" + to_string(Settings::rh_port));
    ContactTracerImpl service(filepath);
    int status = service.initialize();
    if (status < 0) throw runtime_error("loading error!");
    
    grpc::ServerBuilder builder;
    Log("a");
    builder.AddListeningPort(server_address, grpc::InsecureServerCredentials());
    Log("b");
    builder.RegisterService(&service);
    Log("c");
    unique_ptr<grpc::Server> server(builder.BuildAndStart());
    Log("[gRPC] Server listening on %s \n", server_address);
    server->Wait();
}

int Main(char *filepath) {
    LogBase::Inst();

    int ret = 0;
    RunServer(filepath);

    // MessageHandler msg;
    // msg.init(filepath);
    // msg.start();

    return ret;
}


int main( int argc, char **argv ) {
    
    int opt;
    char *filepath = NULL;

    while ((opt = getopt(argc, argv, "f:")) != -1) {
        switch (opt) {
            case 'f':
                if (optarg != NULL) {
                    filepath = optarg;
                } else {
                    Log("Usage: %s [-f central data file path] \n", argv[0]);
                    return -1;
                }
                break;
                                
            default:
                Log("Usage: %s [-f central data file path] \n", argv[0]);
                return -1;
        }
    }
    
    if (filepath == NULL) {
        Log("Usage: %s [-f central data file path] \n", argv[0]);
        return -1;
    }

    try {
        return Main(filepath);
    } catch (std::exception& e) {
        Log("exception: %s", e.what());
    } catch (...) {
        Log("unexpected exception") ;
    }

    return -1;
}

