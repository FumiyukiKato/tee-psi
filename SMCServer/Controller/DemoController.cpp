#include "DemoController.h"

DemoController::DemoController(std::shared_ptr<vector<string>> logs) {
    this->logs = logs;
}

DemoController::~DemoController() {}

/* URL: /log */
crow::response DemoController::dispatch_log_template() {
    return crow::mustache::load_text("log.html");
}

/* URL: /client */
crow::response DemoController::dispatch_client_template() {
    return crow::mustache::load_text("client.html");
}
    
/* URL: /mock_api/remote_attestation */
crow::response DemoController::dispatch_remote_attestation() {
    logs->push_back(getNow() + string("[Request] /remote attestation"));
    usleep(100000);
    logs->push_back(getNow() + string("[Remote Attestation] [INSIDE SGX] start Remote Attestation Protocol"));
    logs->push_back(getNow() + string("[Remote Attestation] [INSIDE SGX] Issue sgx verifiable report"));
    logs->push_back(getNow() + string("[Remote Attestation] [INSIDE SGX] Respond to Client"));
    usleep(2000000);
    logs->push_back(getNow() + string("[Remote Attestation] [INSIDE SGX] Get Attestation Result"));
    logs->push_back(getNow() + string("[Remote Attestation] verified by IAS"));
    usleep(200000);
    logs->push_back(getNow() + string("[Remote Attestation] secure ECDHE is done."));
    crow::json::wvalue res;

    res["session_key"] = "b7b965546aabca4ca5bb21b7093217d5";
    return crow::response(200, res);
}

/* URL: /mock_api/judge_user */
crow::response DemoController::dispatch_judge_user(const crow::request& req) {
    logs->push_back(getNow() + string("[Request] /judge_user"));
    auto user_id = req.url_params.get("user_id");
    crow::json::wvalue res;
    logs->push_back(getNow() + string("[Private Contact Judegment] user id: ") + string(user_id));
    logs->push_back(getNow() + string("[Private Contact Judegment] Loading user's encrypted data from Blockchain"));
    logs->push_back(getNow() + string("STFMZ0ZxWXdjbTBRWTFKTmEwU0IrcDJBNWhXQWxuSSt1VHpuSkZ0blBRND0sVjIzVEVU..."));
    logs->push_back(getNow() + string("[Private Contact Judegment] [INSIDE SGX] using Client session key and decrypt Client's secret key."));
    logs->push_back(getNow() + string("[INSIDE SGX] decryption data 37.477545 140.326492 2020/05/04 12:20:20, ..."));
    logs->push_back(getNow() + string("[Private Contact Judegment] [INSIDE SGX] using Client secret key and decrypt user's data."));
    logs->push_back(getNow() + string("[Private Contact Judegment] [INSIDE SGX] Private Set Intersection..."));
    usleep(1000000);
    logs->push_back(getNow() + string("[Private Contact Judegment] [INSIDE SGX] Encrypt result Negative or Positive and sparial data"));
    logs->push_back(getNow() + string("[Private Contact Judegment] Respond results"));

    std::hash<std::string> str_hash;
    int h = str_hash(string(user_id));

    if (h % 4 == 0) {
        res["result"] = true;
        vector<string> vec ={"37.477545 140.326492 2020/05/04 12:20:20", "37.477545 140.326492 2020/04/30 08:10:00", "37.477545 140.326492 2020/04/10 08:10:00"};
        res["geo_result"] = vec;
    } else if (h % 4 == 1) {
        res["result"] = true;
        vector<string> vec ={"22.646767 134.356662 2020/05/02 02:20:40", "37.477545 140.326492 2020/04/30 08:10:00", "37.477545 140.326492 2020/04/10 08:10:00"};
        res["geo_result"] = vec;
    } else{
        res["result"] = false;
        res["geo_result"] = "";
    };
    return crow::response(200, res);
}

/* URL: /mock_api/next_log */
crow::response DemoController::dispatch_next_log(const crow::request& req) {
    auto index = std::atoi(req.url_params.get("index"));
    crow::json::wvalue res;

    int size;
    if (logs->size() - index < 100) {
        size = logs->size() - index;
    } else {
        size = 100;
    }
    std::vector<string> vec(size);
    std::copy(logs->end() - size, logs->end(), vec.begin());

    res["logs"] = vec;
    res["next"] = logs->size();
    return crow::response(200, res);
}

/* URL: /mock_api/delete_log */
crow::response DemoController::dispatch_delete_log() {
    crow::json::wvalue res;
    logs->clear();
    res["message"] = "ok";
    return crow::response(200, res);
}
