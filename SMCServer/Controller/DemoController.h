#ifndef DEMOCONTROLLER_H
#define DEMOCONTROLLER_H

#include <string>
#include <functional>

#include "UtilityFunctions.h"
#include "crow_all.h"

using namespace std;
using namespace util;

class DemoController {

public:
    DemoController(std::shared_ptr<vector<string>> logs);
    virtual ~DemoController();
    
    crow::response dispatch_log_template();
    crow::response dispatch_client_template();
    crow::response dispatch_remote_attestation();
    crow::response dispatch_judge_user(const crow::request& req);
    crow::response dispatch_next_log(const crow::request& req);
    crow::response dispatch_delete_log();

protected:
    std::shared_ptr<vector<string>> logs = NULL;

};

#endif
