#define CROW_ENABLE_SSL

#include "crow_all.h"
#include <string>
#include <vector>

#include "PsiService.h"
#include "PsiController.h"
#include "DemoController.h"
#include "LogBase.h"
#include "AuthMiddleware.cpp"

int Main(char *filepath) {
    LogBase::Inst();
    int ret = 0;
  
    // デモのために作ったログ表示機能
    std::vector<string> log_vec = {};
    auto logs = std::make_shared<vector<string> >(log_vec);

    // service 初期化
    PsiService service;
    service.start(filepath);
    PsiService *service_ptr = &service;

    // controller 初期化
    PsiController psi_controller_instance(&service, logs);
    PsiController *psi_controller = &psi_controller_instance;

    DemoController demo_controller_instance(logs);
    DemoController *demo_controller = &demo_controller_instance;

    // application 初期化
    // 認証のミドルウェアはめんどいので通さない
    crow::App<NopMiddleware> app;

    /* Routing */

    // with url parameter ?auth_token='xxxxxxxxxxx'
    // all other parameter must be in json format

    // /remote_attestation_mock
    //   - request parameter
    //    - none
    //   - response parameter
    //    nn- shared key: string
    //    - session_token: string
    //   - description
    //    - mock-up remote attestation
    //     - We consider the SGX server trusted.
    //     - here, simply to accept shared key given by SGX server
    //    - We can simplify Remote Attestation as mock. Remote attestation includes multiple communications with IAS and server with SGX. The purpose is to trust the SGX server and to exchange Session Key between SGX and client.
    //    - Normally, it is unnatural to do this with stateless HTTP, but the client-side should send out requests continuously, and the server-side should manage the state with token.
    CROW_ROUTE(app, "/remote_attestation_mock")
        .methods("GET"_method)
        ([psi_controller](const crow::request& req){
        return psi_controller->dispatch_remote_attestation_mock(req);
    });

    // - /judge_contact
    //  - request parameter
    //      {
    //        user_id: string
    //        secret_key: string
    //        gcm_tag: string
    //        session_token: string
    //      }
    //     - response parameter
    //       { risk_level: string }
    //     - description
    //       - before this, need to do mock-up remote attestation and get the shared key.
    //       - Properly speaking, this should be done in the same session as remote attestation.
    //       - Only SGX can access a shared key. So, this history data reach to SGX securely.
    CROW_ROUTE(app, "/judge_contact")
        .methods("GET"_method)
        ([psi_controller](const crow::request& req){
        return psi_controller->dispatch_judge_contact(req);
    });

    // - /report_infection
    //  - request parameter
    //      {
    //        user_id: string
    //        secret_key: string
    //        gcm_tag: string
    //        session_token: string
    //      }
    //     - response parameter
    //       { message: string }
    //     - description
    //         - before this, need to do mock-up remote attestation and get the shared key.
    //         - when this request
    CROW_ROUTE(app, "/report_infection")
        .methods("POST"_method)
        ([psi_controller, &logs](const crow::request& req){
        return psi_controller->dispatch_report_infection(req);
    });

    // - /get_public_key
    //  - request parameter
    //      { session_token: string }
    //     - response parameter
    //      { public_key: string, gcm_tag: string }
    CROW_ROUTE(app, "/get_public_key")
        .methods("GET"_method)
        ([psi_controller, &logs](const crow::request& req){
        return psi_controller->dispatch_get_public_key(req);
    });


    /* デモのために作ったAPIたち */
    /* 基本的にもういらないと思っているが... */
    CROW_ROUTE(app, "/log")
        .methods("GET"_method)
    ([demo_controller]() {
        return demo_controller->dispatch_log_template();
    });

    CROW_ROUTE(app, "/client")
        .methods("GET"_method)
    ([demo_controller]() {
        return demo_controller->dispatch_client_template();
    });

    CROW_ROUTE(app, "/mock_api/remote_attestation")
        .methods("GET"_method)
    ([demo_controller](){
        return demo_controller->dispatch_remote_attestation();
    });

    CROW_ROUTE(app, "/mock_api/judge_user")
        .methods("GET"_method)
    ([demo_controller](const crow::request& req){
        return demo_controller->dispatch_judge_user(req);
    });

    CROW_ROUTE(app, "/mock_api/next_log")
        .methods("GET"_method)
    ([demo_controller](const crow::request& req){
        return demo_controller->dispatch_next_log(req);
    });

    CROW_ROUTE(app, "/mock_api/delete_log")
        .methods("GET"_method)
    ([demo_controller](){
        return demo_controller->dispatch_delete_log();
    });

    //   crow::logger::setLogLevel(crow::LogLevel::Debug);

    app
        .port(8080)
        .multithreaded()
        .ssl_file("../server.crt", "../server.key")
        .run();
}

int main( int argc, char **argv ) {
    
    int opt;
    char *filepath = NULL;
    filepath = "../data/central_data.txt";

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