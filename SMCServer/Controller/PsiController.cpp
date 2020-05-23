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
    int status = this->service->remoteAttestationMock(token, sk);
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

    uint8_t *sKey = NULL;
    auto sKey_str = json_req["secret_key"].s();
    if (GCMTAG_SIZE != StringToByteArray(Base64decode(sKey_str), &sKey)) {
        res["error"] = "invalid format secret_key";
        return crow::response(400, res);
    };

    uint8_t *gcm_tag = NULL;
    auto gcm_tag_str = json_req["gcm_tag"].s();
    if (GCMTAG_SIZE != StringToByteArray(Base64decode(gcm_tag_str), &gcm_tag)) {
        res["error"] = "invalid format gcm_tag";
        return crow::response(400, res);
    };

    uint8_t *data;
    size_t data_size;
    uint8_t *load_data_gcm_tag;
    int status = this->service->loadDataFromBlockChain(
        user_id,
        session_token,
        load_data_gcm_tag,
        sKey,
        data,
        &data_size
    );
    if (status < 0) {
        res["error"] = "curl error";
        return crow::response(500, res);
    }
    
    uint8_t result[data_size];
    size_t history_num = data_size / 19; // data size
    uint8_t risk_level[E_RISKLEVEL_SIZE];
    uint8_t result_mac[GCMTAG_SIZE] = {0};
    status = this->service->judgeContact(
        session_token,
        gcm_tag,
        data,
        data_size,
        risk_level,
        result,
        history_num,
        result_mac
    );
    if (status < 0) {
        res["error"] = "internal server error";
        return crow::response(500, res);
    }
    
    
    std::cout << risk_level << std::endl;
    std::cout << result_mac << std::endl;
    res["risk_level"] = Base64encodeUint8(risk_level, E_RISKLEVEL_SIZE);
    res["gcm_tag"] = Base64encodeUint8(result_mac, GCMTAG_SIZE);
    return crow::response(200, res);
}

crow::response PsiController::dispatch_report_infection(const crow::request& req) {
    auto json_req = crow::json::load(req.body);
    crow::json::wvalue res;
    
    if (!json_req || !json_req.has("user_id")
        ||!json_req.has("session_token") || !json_req.has("gcm_tag")
        ||!json_req.has("sKey")) {
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

    uint8_t *sKey = NULL;
    auto sKey_str = json_req["sKey"].s();
    if (GCMTAG_SIZE != StringToByteArray(Base64decode(sKey_str), &sKey)) {
        res["error"] = "invalid format sKey";
        return crow::response(400, res);
    };

    uint8_t *gcm_tag = NULL;
    auto gcm_tag_str = json_req["gcm_tag"].s();
    if (GCMTAG_SIZE != StringToByteArray(Base64decode(gcm_tag_str), &gcm_tag)) {
        res["error"] = "invalid format gcm_tag";
        return crow::response(400, res);
    };

    uint8_t *data;
    size_t data_size;
    int status = this->service->loadDataFromBlockChain(
        user_id,
        session_token,
        gcm_tag,
        sKey,
        data,
        &data_size
    );

    status = this->service->storeInfectedData(

    );


    // モックのためにログを吐き出す
    this->logs->push_back(getNow() + string("[Private Contact Judegment] Loading user's encrypted data from Blockchain"));
    this->logs->push_back(getNow() + string("STFMZ0ZxWXdjbTBRWTFKTmEwU0IrcDJBNWhXQWxuSSt1VHpuSkZ0blBRND0sVjIzVEVU..."));
    this->logs->push_back(getNow() + string("[Private Contact Judegment] [INSIDE SGX] using Client session key and decrypt Client's secret key."));
    this->logs->push_back(getNow() + string("[Private Contact Judegment] [INSIDE SGX] store DB inside enclave."));
    res["message"] = "ok";
    return crow::response(200, res);
}