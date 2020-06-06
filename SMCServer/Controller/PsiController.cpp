#include "PsiController.h"

PsiController::PsiController(PsiService *service, std::shared_ptr<vector<string>> logs) {
    this->service = service;
    this->logs = logs;
}

PsiController::~PsiController() {
    delete this->service;
}

/* URL: /remote_attestation_mock */
crow::response PsiController::dispatch_remote_attestation_mock(const crow::request& req) {
    auto json_req = crow::json::load(req.body);
    crow::json::wvalue res;
    
    if (json_req) {
        res["error"] = "invalid parameter, parameter is not needed";
        return crow::response(400, res);
    }
    
    uint8_t sk[SESSIONKEY_SIZE];
    uint8_t token[SESSIONTOKEN_SIZE];
    int status = service->remoteAttestationMock(token, sk);
    if (status < 0) {
        res["error"] = "internal server error";
        return crow::response(500, res);
    }

    res["shared_key"] = ByteArrayToString(sk, SESSIONKEY_SIZE);
    res["session_token"] = ByteArrayToString(token, SESSIONTOKEN_SIZE);
    return crow::response(200, res);
};

crow::response PsiController::dispatch_judge_contact(const crow::request& req) {
    auto json_req = crow::json::load(req.body);
    crow::json::wvalue res;
    
    if (!json_req || !json_req.has("user_id") || !json_req.has("secret_key") ||
        !json_req.has("gcm_tag") || !json_req.has("session_token")) {
        res["error"] = "invalid json format";
        return crow::response(400, res);
    }
    
    std::string user_id = json_req["user_id"].s();

    uint8_t *session_token = NULL;
    auto session_token_str = json_req["session_token"].s();
    if (SESSIONTOKEN_SIZE != HexStringToByteArray(session_token_str, &session_token)) {
        res["error"] = "invalid format session token";
        return crow::response(400, res);
    };

    uint8_t *secret_key = NULL;
    auto secret_key_str = json_req["secret_key"].s();
    if (GCMTAG_SIZE != StringToByteArray(Base64decode(secret_key_str), &secret_key)) {
        res["error"] = "invalid format secret_key";
        return crow::response(400, res);
    };

    uint8_t *secret_key_gcm_tag = NULL;
    auto gcm_tag_str = json_req["gcm_tag"].s();
    if (GCMTAG_SIZE != StringToByteArray(Base64decode(gcm_tag_str), &secret_key_gcm_tag)) {
        res["error"] = "invalid format gcm_tag";
        return crow::response(400, res);
    };

    string mock_file;
    if (json_req.has("mock_file")) {
        mock_file = json_req["mock_file"].s();
    }

    const size_t total_result_size = E_RISKLEVEL_SIZE + UUID_SIZE + TIMESTAMP_SIZE;
    uint8_t result[total_result_size];
    uint8_t signature[SGX_ECP256_DS_SIZE];
    uint8_t result_mac[GCMTAG_SIZE];
    int status = service->judgeContact(
        user_id,
        session_token,
        secret_key,
        secret_key_gcm_tag,
        result,
        result_mac,
        signature,
        mock_file
    );
    if (status < 0) {
        res["error"] = "internal server error";
        return crow::response(500, res);
    }
    
    res["risk_level"] = Base64encodeUint8(result, total_result_size);
    res["gcm_tag"] = Base64encodeUint8(result_mac, GCMTAG_SIZE);
    res["sgx_signature"] = Base64encodeUint8(signature, SGX_ECP256_DS_SIZE);
    return crow::response(200, res);
}

crow::response PsiController::dispatch_report_infection(const crow::request& req) {
    auto json_req = crow::json::load(req.body);
    crow::json::wvalue res;
    
    if (!json_req || !json_req.has("user_id")
        ||!json_req.has("session_token") || !json_req.has("gcm_tag")
        ||!json_req.has("secret_key")) {
        res["error"] = "invalid json format";
        return crow::response(400, res);
    }

    std::string user_id = json_req["user_id"].s();

    uint8_t *session_token = NULL;
    auto session_token_str = json_req["session_token"].s();
    if (SESSIONTOKEN_SIZE != HexStringToByteArray(session_token_str, &session_token)) {
        res["error"] = "invalid format session token";
        return crow::response(400, res);
    };

    uint8_t *encrypted_secret_key = NULL;
    auto secret_key_str = json_req["secret_key"].s();
    if (GCMTAG_SIZE != StringToByteArray(Base64decode(secret_key_str), &encrypted_secret_key)) {
        res["error"] = "invalid format secret_key";
        return crow::response(400, res);
    };

    uint8_t *secret_key_gcm_tag = NULL;
    auto gcm_tag_str = json_req["gcm_tag"].s();
    if (GCMTAG_SIZE != StringToByteArray(Base64decode(gcm_tag_str), &secret_key_gcm_tag)) {
        res["error"] = "invalid format gcm_tag";
        return crow::response(400, res);
    };

    string mock_file;
    if (json_req.has("mock_file")) {
        mock_file = json_req["mock_file"].s();
    }
    
    int status = service->loadAndStoreInfectedData(
        user_id,
        session_token,
        encrypted_secret_key,
        secret_key_gcm_tag,
        mock_file
    );
    if (status < 0) {
        res["error"] = "internal server error";
        return crow::response(500, res);
    }

    // モックのためにログを吐き出す
    // this->logs->push_back(getNow() + string("[Private Contact Judegment] Loading user's encrypted data from Blockchain"));
    // this->logs->push_back(getNow() + string("STFMZ0ZxWXdjbTBRWTFKTmEwU0IrcDJBNWhXQWxuSSt1VHpuSkZ0blBRND0sVjIzVEVU..."));
    // this->logs->push_back(getNow() + string("[Private Contact Judegment] [INSIDE SGX] using Client session key and decrypt Client's secret key."));
    // this->logs->push_back(getNow() + string("[Private Contact Judegment] [INSIDE SGX] store DB inside enclave."));
    res["message"] = "ok";
    return crow::response(200, res);
}

crow::response PsiController::dispatch_get_public_key(const crow::request& req) {
    auto json_req = crow::json::load(req.body);
    crow::json::wvalue res;
    
    if (!json_req ||!json_req.has("session_token")) {
        res["error"] = "invalid json format";
        return crow::response(400, res);
    }

    uint8_t *session_token = NULL;
    auto session_token_str = json_req["session_token"].s();
    if (SESSIONTOKEN_SIZE != HexStringToByteArray(session_token_str, &session_token)) {
        res["error"] = "invalid format session token";
        return crow::response(400, res);
    };

    uint8_t public_key[SGX_ECP256_KEY_SIZE*2];
    uint8_t gcm_tag[GCMTAG_SIZE] = {0};
    int status = service->getPublicKey(
        session_token,
        public_key,
        gcm_tag
    );
    if (status < 0) {
        res["error"] = "internal server error";
        return crow::response(500, res);
    }
    
    res["public_key"] = Base64encodeUint8(public_key, SGX_ECP256_KEY_SIZE*2);
    res["gcm_tag"] = Base64encodeUint8(gcm_tag, GCMTAG_SIZE);
    return crow::response(200, res);
}