#define CROW_ENABLE_SSL
#include "crow_all.h"
#include <random>

#define STR_LEN 32

std::random_device rd{};

void generateRandomHexStirng(char str[])
{
  char hex_characters[]={'0','1','2','3','4','5','6','7','8','9','A','B','C','D','E','F'};
  for(int i=0;i<STR_LEN;i++) {
    str[i]=hex_characters[rd()%16];
  }
  str[STR_LEN]=0;
};

struct ExampleMiddleware 
{
    std::string tmpToken;

    ExampleMiddleware() 
    {
      char chToken[STR_LEN];
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

int main()
{
  crow::App<ExampleMiddleware> app;

  
  /* Routing */

  // with url parameter ?auth_token='xxxxxxxxxxx'
  // all other parameter must be in json format

  // - /remote_attestation_mock
  //     - request parameter
  //         - none
  //     - response parameter
  //         - shared key: bytes (128bit or 256bit?)
  //         - id_token: string (for key identity)
  //     - description
  //         - mock-up remote attestation
  //             - We consider the SGX server trusted.
  //             - here, simply to accept shared key given by SGX server
  //         - We can simplify Remote Attestation as mock. Remote attestation includes multiple communications with IAS and server with SGX. The purpose is to trust the SGX server and to exchange Session Key between SGX and client.
  //         - Normally, it is unnatural to do this with stateless HTTP, but the client-side should send out requests continuously, and the server-side should manage the state with token.
  CROW_ROUTE(app, "/remote_attestation_mock")
    .methods("GET"_method)
  ([](const crow::request& req){
    auto x = crow::json::load(req.body);
    crow::json::wvalue res;
    
    if (!x) {
        res["error"] = "invalid json format";
        return crow::response(400, res);
    }
    
    res["shared_key"] = "B0702B28101BFCAA36965C6338688530";
    res["id_token"] = std::string("B0702B28101BFCAA36965C6338688530").c_str();
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
  ([](const crow::request& req){
    auto x = crow::json::load(req.body);
    crow::json::wvalue res;
    
    if (!x) {
        res["error"] = "invalid json format";
        return crow::response(400, res);
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
  ([](const crow::request& req){
    auto x = crow::json::load(req.body);
    crow::json::wvalue res;
    
    if (!x) {
        res["error"] = "invalid json format";
        return crow::response(400, res);
    }
    
    res["message"] = "ok";
    return crow::response(200, res);
  });


  app
    .port(8080)
    .ssl_file("../server.crt", "../server.key")
    .run();
}