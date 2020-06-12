#include "crow_all.h"
#include <random>

#define TOKEN_LEN 32

// 外部に晒すのでので申し訳程度にtokenで認証するミドルウェアをかます
struct AuthMiddleware  {
    std::string tmpToken;

    AuthMiddleware() {
      char chToken[TOKEN_LEN];
      // generateRandomHexStirng(chToken);
      // tmpToken = chToken;
      tmpToken = "B0702B28101BFCAA36965C6338688530"; // 共有する方法を考えるのがめんどくさいので固定にしている
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
            str[i]=hex_characters[rand()%16];
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

struct NopMiddleware 
{

    NopMiddleware() {}

    struct context {};

    void before_handle(crow::request& /*req*/, crow::response& /*res*/, context& /*ctx*/) {}

    void after_handle(crow::request& /*req*/, crow::response& /*res*/, context& /*ctx*/) {}
};