#define CROW_ENABLE_SSL

#include <random>
#include "crow_all.h"
#include <string>

#include "PsiService.h"
#include "LogBase.h"

#define TOKEN_LEN 32
#define E_RISKLEVEL_SIZE 1
#define GCMTAG_SIZE 16

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
    
    uint8_t sk[SESSIONKEY_SIZE];
    uint8_t token[SESSIONTOKEN_SIZE];
    int status = service_ptr->remoteAttestationMock(token, sk);
    if (status < 0) {
        res["error"] = "internal server error";
        return crow::response(500, res);
    }

    res["shared_key"] = ByteArrayToString(sk, SESSIONKEY_SIZE);
    res["session_token"] = ByteArrayToString(token, SESSIONTOKEN_SIZE);
    return crow::response(200, res);
  });

  // - /judge_contact
  //     - request parameter
  //         - history: bytes(encrypted with shared key)
  //         - history_num: integer
  //         - token: string
  //         - gcm: string
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
    
    if (!json_req || !json_req.has("history") || !json_req.has("history_num") ||
        !json_req.has("session_token") || !json_req.has("gcm_tag")) {
        res["error"] = "invalid json format";
        return crow::response(400, res);
    }
    
    uint8_t *session_token = NULL;
    auto session_token_str = json_req["session_token"].s();
    if (SESSIONTOKEN_SIZE != HexStringToByteArray(session_token_str, &session_token)) {
        res["error"] = "invalid format session token";
        return crow::response(400, res);
    };

    uint8_t *gcm_tag = NULL;
    auto gcm_tag_str = json_req["gcm_tag"].s();
    if (GCMTAG_SIZE != StringToByteArray(Base64decode(gcm_tag_str), &gcm_tag)) {
        res["error"] = "invalid format gcm_tag";
        return crow::response(400, res);
    };

    size_t history_num = json_req["history_num"].i();
    if(history_num < 1) {
        res["error"] = "invalid history size";
        return crow::response(400, res);
    }

    auto history_data = json_req["history"];
    uint8_t *encrypted_history_data = NULL;
    size_t data_size = StringToByteArray(Base64decode(history_data.s()), &encrypted_history_data);
    uint8_t result[history_num];
    uint8_t risk_level[E_RISKLEVEL_SIZE];
    uint8_t result_mac[GCMTAG_SIZE] = {0};
    int status = service_ptr->judgeContact(
        session_token,
        gcm_tag,
        encrypted_history_data,
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
  });

  // - /report_infection
  //     - request_parameter
  //         - user_id(block-chain key): bytes(encrypted with shared key)
  //     - response parameter
  //         - none
  //     - description
  //         - before this, need to do mock-up remote attestation and get the shared key.
  //         - when this request
  CROW_ROUTE(app, "/report_infection")
      .methods("GET"_method)
  ([service_ptr](const crow::request& req){
    auto json_req = crow::json::load(req.body);
    crow::json::wvalue res;
    
    if (!json_req || !json_req.has("user_id")) {
        res["error"] = "invalid json format";
        return crow::response(400, res);
    }

    std::string user_id = json_req["user_id"].s();
    int status = service_ptr->loadDataFromBlockChain(user_id);
    
    res["message"] = "ok";
    return crow::response(200, res);
  });

  crow::logger::setLogLevel(crow::LogLevel::Debug);

  app
    .port(8080)
    .multithreaded()
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