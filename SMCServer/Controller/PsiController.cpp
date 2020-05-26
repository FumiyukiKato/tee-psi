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

    uint8_t risk_level[E_RISKLEVEL_SIZE];
    uint8_t result_mac[GCMTAG_SIZE] = {0};
    int status = service->judgeContact(
        user_id,
        session_token,
        secret_key,
        secret_key_gcm_tag,
        risk_level,
        result_mac
    );
    if (status < 0) {
        res["error"] = "internal server error";
        return crow::response(500, res);
    }
    
    res["risk_level"] = Base64encodeUint8(risk_level, E_RISKLEVEL_SIZE);
    res["gcm_tag"] = Base64encodeUint8(result_mac, GCMTAG_SIZE);
    return crow::response(200, res);
}

crow::response PsiController::dispatch_report_infection(const crow::request& req) {
    auto json_req = crow::json::load(req.body);
    crow::json::wvalue res;
    Log("dispatch");
    
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
    
    int status = service->loadAndStoreInfectedData(
        user_id,
        session_token,
        encrypted_secret_key,
        secret_key_gcm_tag
    );

    // モックのためにログを吐き出す
    this->logs->push_back(getNow() + string("[Private Contact Judegment] Loading user's encrypted data from Blockchain"));
    this->logs->push_back(getNow() + string("STFMZ0ZxWXdjbTBRWTFKTmEwU0IrcDJBNWhXQWxuSSt1VHpuSkZ0blBRND0sVjIzVEVU..."));
    this->logs->push_back(getNow() + string("[Private Contact Judegment] [INSIDE SGX] using Client session key and decrypt Client's secret key."));
    this->logs->push_back(getNow() + string("[Private Contact Judegment] [INSIDE SGX] store DB inside enclave."));
    res["message"] = "ok";
    return crow::response(200, res);
}