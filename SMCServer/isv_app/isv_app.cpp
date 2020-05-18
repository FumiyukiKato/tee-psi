#define CROW_ENABLE_SSL

#include <random>
#include "crow_all.h"
#include <string>

#include "PsiService.h"
#include "LogBase.h"

#define TOKEN_LEN 32
#define E_GEODATA_SIZE 20
#define E_TIMESTAMP_SIZE 30
#define E_RISKLEVEL_SIZE 1

std::random_device rd{};

struct AuthMiddleware  {
    std::string tmpToken;

    AuthMiddleware() {
      char chToken[TOKEN_LEN];
      // generateRandomHexStirng(chToken);
      // tmpToken = chToken;
      tmpToken = "B0702B28101BFCAA36965C6338688530";
      std::cout << "[TOKEN INFO] Temporary token is token=" << tmpToken << std::endl;
    }

    int authenticate(const crow::request& req, std::string tmpToken) {
        auto token = req.url_params.get("auth_token");
        if (!token) return -1;
        if (token == tmpToken) return 0;
        std::cout << "[TOKEN INFO] invalid token: " << token << std::endl;
        return -1;
    };

    void generateRandomHexStirng(char str[]) {
        char hex_characters[]={'0','1','2','3','4','5','6','7','8','9','A','B','C','D','E','F'};
        for(int i=0;i<TOKEN_LEN;i++) {
            str[i]=hex_characters[rd()%16];
        }
        str[TOKEN_LEN]=0;
    };
    
    struct context {};

    void before_handle(crow::request& req, crow::response& res, context& /*ctx*/) {
        if (authenticate(req, tmpToken) < 0) {
          crow::json::wvalue json;
          json["error"] = "authentication failed";
          res = crow::response(400, json);
          res.end();
          return;
        }
    }

    void after_handle(crow::request& /*req*/, crow::response& /*res*/, context& /*ctx*/) {}
};

int Main(char *filepath) {
  LogBase::Inst();
  int ret = 0;

  Log("[Main] preparing service...");
  PsiService service;
  service.start(filepath);
  Log("[Main] service is ready!");
  PsiService *service_ptr = &service;

  crow::App<AuthMiddleware> app;
  /* Routing */

  // with url parameter ?auth_token='xxxxxxxxxxx'
  // all other parameter must be in json format

  // - /remote_attestation_mock
  //     - request parameter
  //         - none
  //     - response parameter
  //         - shared key: bytes (256bit)
  //         - id_token: string (256bit)
  //     - description
  //         - mock-up remote attestation
  //             - We consider the SGX server trusted.
  //             - here, simply to accept shared key given by SGX server
  //         - We can simplify Remote Attestation as mock. Remote attestation includes multiple communications with IAS and server with SGX. The purpose is to trust the SGX server and to exchange Session Key between SGX and client.
  //         - Normally, it is unnatural to do this with stateless HTTP, but the client-side should send out requests continuously, and the server-side should manage the state with token.
  CROW_ROUTE(app, "/remote_attestation_mock")
    .methods("GET"_method)
  ([service_ptr](const crow::request& req){
    auto json_req = crow::json::load(req.body);
    crow::json::wvalue res;
    
    if (json_req) {
        res["error"] = "invalid parameter, parameter is not needed";
        return crow::response(400, res);
    }
    
    uint8_t token[KEY_SIZE];
    uint8_t sk[SESSIONTOKEN_SIZE];
    int status = service_ptr->remoteAttestationMock(token, sk);
    if (status < 0) {
        res["error"] = "internal server error";
        return crow::response(500, res);
    }

    res["shared_key"] = Base64encodeUint8(sk, KEY_SIZE);
    res["session_token"] = Base64encodeUint8(token, SESSIONTOKEN_SIZE);
    return crow::response(200, res);
  });

  // - /judge_contact
  //     - request parameter
  //         - history: bytes(encrypted with shared key)
  //         - token: string
  //     - response parameter
  //         - risk_level: int
  //     - description
  //         - before this, need to do mock-up remote attestation and get the shared key.
  //         - Properly speaking, this should be done in the same session as remote attestation.
  //         - Only SGX can access a shared key. So, this history data reach to SGX securely.
  CROW_ROUTE(app, "/judge_contact")
      .methods("GET"_method)
  ([service_ptr](const crow::request& req){
    auto json_req = crow::json::load(req.body);
    crow::json::wvalue res;
    
    if (!json_req || !json_req.has("history") || 
        !json_req.has("session_token") || !json_req.has("gcm_tag") ||
        !json_req["history"][0].has("geohash")) {
        res["error"] = "invalid json format";
        return crow::response(400, res);
    }
    
    uint8_t *session_token = NULL;
    auto session_token_str = json_req["session_token"].s();
    StringToByteArray(session_token_str, &session_token);

    // uint8_t *gcm_tag = NULL;
    // auto gcm_tag_str = json_req["gcm_tag"].s();
    // StringToByteArray(gcm_tag_str, &gcm_tag);

    auto history_data = json_req["history"];
    size_t history_size = history_data.size();
    std::cout << "historysize: " << history_size << std::endl;
    if(history_size < 0) {
        res["error"] = "invalid history size";
        return crow::response(400, res);
    }

    size_t geo_data_size = E_GEODATA_SIZE * history_size;
    size_t time_data_size = E_TIMESTAMP_SIZE * history_size;
    uint8_t encrypted_geohash_data[E_GEODATA_SIZE * history_size];
    uint8_t encrypted_timestamp_data[E_TIMESTAMP_SIZE * history_size];
    for (int i=0; i<history_size; i++) {
        uint8_t *g_buf = NULL;
        uint8_t *t_buf = NULL;
        if(E_GEODATA_SIZE == StringToByteArray(Base64decode(history_data[i]["geohash"].s()), &g_buf)) {
            memcpy(&encrypted_geohash_data[i*E_GEODATA_SIZE], g_buf, E_GEODATA_SIZE);
        } else {
            res["error"] = "invalid geohash code size, not 24";
            return crow::response(400, res);
        }
        if(E_TIMESTAMP_SIZE == StringToByteArray(Base64decode(history_data[i]["timestamp"].s()), &t_buf)) {
            memcpy(&encrypted_timestamp_data[i*E_TIMESTAMP_SIZE], t_buf, E_TIMESTAMP_SIZE);
        } else {
            res["error"] = "invalid timestamp code size, not 24";
            return crow::response(400, res);
        }
    }
    
    uint8_t result[history_size];
    uint8_t risk_level[E_RISKLEVEL_SIZE];
    int status = service_ptr->judgeContact(
        session_token,
        encrypted_geohash_data,
        geo_data_size,
        encrypted_timestamp_data,
        time_data_size,
        risk_level,
        result,
        history_size
    );
    if (status < 0) {
        res["error"] = "internal server error";
        return crow::response(500, res);
    }

    res["risk_level"] = 1;
    return crow::response(200, res);
  });

  // - /report_infection
  //     - request_parameter
  //         - user_id(block-chain key): bytes(encrypted with shared key)
  //         - token: string
  //     - response parameter
  //         - none
  //     - description
  //         - before this, need to do mock-up remote attestation and get the shared key.
  //         - when this request
  CROW_ROUTE(app, "/report_infection")
      .methods("GET"_method)
  ([service_ptr](const crow::request& req){
    auto x = crow::json::load(req.body);
    crow::json::wvalue res;
    
    if (!x) {
        res["error"] = "invalid json format";
        return crow::response(400, res);
    }
    
    res[""] = "ok";
    return crow::response(200, res);
  });

  app
    .port(8081)
    .ssl_file("../server.crt", "../server.key")
    .run();
}

int main( int argc, char **argv ) {
    
    int opt;
    char *filepath = NULL;
    filepath = "../data/sample.txt";

    while ((opt = getopt(argc, argv, "f:")) != -1) {
        switch (opt) {
            case 'f':
                if (optarg != NULL) {
                    filepath = optarg;
                } else {
                    Log("Usage: %s [-f central data file path] \n", argv[0]);
                    // return -1;
                }
                break;
                                
            default:
                Log("Usage: %s [-f central data file path] \n", argv[0]);
                // return -1;
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