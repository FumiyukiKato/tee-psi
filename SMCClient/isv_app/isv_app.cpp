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
#include <string.h>

#include "LogBase.h"
#include "NetworkManager.h"
#include "MessageManager.h"
#include "UtilityFunctions.h"

using namespace util;

int Main(ClientMode mode, char *filepath) {
    LogBase::Inst();

    int ret = 0;

    MessageManager *vm = MessageManager::getInstance();
    vm->init(mode, filepath);
    vm->start();

    return ret;
}


int main( int argc, char **argv ) {

    int opt;
    ClientMode mode = P2P;
    char *filepath = "hash1.txt";

    while ((opt = getopt(argc, argv, "f:m:")) != -1) {
        switch (opt) {
            case 'f':
                if (optarg != NULL && strcmp(optarg, "-m")) {
                    filepath = optarg;
                } else {
                    Log("Usage: %s [-f file path] [-m mode]\n", argv[0]);
                    return -1;
                }
                break;

            case 'm':
                if (strcmp(optarg, "central") == 0) {
                    mode = CENTRAL;
                } else if (strcmp(optarg, "p2p") == 0) {
                    mode = P2P;
                } else {
                    Log("Usage: %s [-f file path] [-m mode]\n", argv[0]);
                    return -1;
                }
                break;

            default:
                Log("Usage: %s [-f file path] [-m mode]\n", argv[0]);
                return -1;
        }
    }
    
    try {
        int ret = Main(mode, filepath);
        return ret;
    } catch (std::exception & e) {
        Log("exception: %s", e.what());
    } catch (...) {
        Log("unexpected exception");
    }

    return -1;
}
