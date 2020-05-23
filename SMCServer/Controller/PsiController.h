#ifndef PSICONTROLLER_H
#define PSICONTROLLER_H

#include <string>

#include "UtilityFunctions.h"
#include "PsiService.h"
#include "crow_all.h"

#define E_RISKLEVEL_SIZE 1
#define GCMTAG_SIZE 16

using namespace std;
using namespace util;

class PsiController {

public:
    PsiController(PsiService *psiservcie, std::shared_ptr<vector<string>> logs);
    virtual ~PsiController();
    
    crow::response dispatch_remote_attestation_mock(const crow::request& req);
    crow::response dispatch_judge_contact(const crow::request& req);
    crow::response dispatch_report_infection(const crow::request& req);

    
private:
    sgx_status_t initEnclave();
    uint32_t getExtendedEPID_GID();

protected:
    PsiService *service = NULL;
    std::shared_ptr<vector<string>> logs = NULL;

};

#endif
