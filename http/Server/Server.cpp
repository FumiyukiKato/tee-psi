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
        auto token = req.url_params.get("token");
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

  CROW_ROUTE(app, "/remote_attestation_mock")
    .methods("GET"_method)
  ([](const crow::request& req){
    auto x = crow::json::load(req.body);
    crow::json::wvalue res;
    
    if (!x) {
        res["error"] = "invalid json format";
        return crow::response(400, res);
    }
    
    res["message"] = "Hello, World!";
    return crow::response(200, res);
  });

  CROW_ROUTE(app, "/judge_contact")
      .methods("GET"_method)
  ([](const crow::request& req){
    auto x = crow::json::load(req.body);
    crow::json::wvalue res;
    
    if (!x) {
        res["error"] = "invalid json format";
        return crow::response(400, res);
    }
    
    res["message"] = "Hello, World!";
    return crow::response(200, res);
  });

  CROW_ROUTE(app, "/report_infection")
      .methods("GET"_method)
  ([](const crow::request& req){
    auto x = crow::json::load(req.body);
    crow::json::wvalue res;
    
    if (!x) {
        res["error"] = "invalid json format";
        return crow::response(400, res);
    }
    
    res["message"] = "Hello, World!";
    return crow::response(200, res);
  });

  app
    .port(8080)
    .ssl_file("../server.crt", "../server.key") // curl --cacert path/to/server.crt https://localhost:50001
    .run();
}