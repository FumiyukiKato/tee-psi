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

#ifndef GENERALSETTINGS_H
#define GENERALSETTINGS_H

#include <string>

using namespace std;

namespace Settings {
    static int rh_port         = 22225;
    static string rh_host      = "localhost";

    static string server_crt   = std::getenv("SERVER_CRT_PATH"); //certificate for the HTTPS connection between the SP and the App
    static string server_key   = std::getenv("SERVER_KEY_PATH"); //private key for the HTTPS connection

    static string spid         = std::getenv("RA_SPID"); //SPID provided by Intel after registration for the IAS service
    static const char *ias_crt = std::getenv("INTEL_CA"); //location of the certificate send to Intel when registring for the IAS
    // static string ias_url      = "https://test-as.sgx.trustedservices.intel.com:443/attestation/sgx/v3/";
    static string ias_url      = "https://api.trustedservices.intel.com/sgx/dev/attestation/v4/"; 

    static string subscription_key   = std::getenv("AS_PRIMARY_KEY");

    // sgxのattestation serviceのAPIの仕様書
    // version 4 動いているの？
    // https://api.trustedservices.intel.com/documents/IAS-API-Spec-rev-4.0.pdf

    // latest 
    // version 6
    // https://api.trustedservices.intel.com/documents/sgx-attestation-api-spec.pdf
    static string data_file_path = "./central_data.txt";
}

#endif
