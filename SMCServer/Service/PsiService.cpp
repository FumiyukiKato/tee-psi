#include "PsiService.h"

Clocker clocker;

PsiService::PsiService() {
    curl_global_init(CURL_GLOBAL_DEFAULT);
}

PsiService::~PsiService() {
    delete this->enclave;
}

void PsiService::start(string path) {
    Log("[Service] enclave init");
    clocker = Clocker("Initialize SGX");
    clocker.start();
    sgx_status_t ret = this->initEnclave();
    if (SGX_SUCCESS != ret) {
        Log("Error, call initEnclave fail", log::error);
        return;
    }

    sgx_status_t status;
    uint8_t salt[SALT_SIZE];
    ret = initialize(this->enclave->getID(), &status, salt);
    clocker.stop();
    uint8_t * filedata = NULL;
    int file_size = 0;
    clocker = Clocker("Read central data");
    clocker.start();
    file_size = ReadFileToBuffer(path, &filedata);
    if (file_size <= 0) {
        return ;
    }
    clocker.stop();
    Log("[Service] loading central data");
    clocker = Clocker("Uploading central data");
    clocker.start();
    ret = uploadCentralData(this->enclave->getID(), &status, filedata, file_size);
    if ((SGX_SUCCESS != ret) || (SGX_SUCCESS != status)) {
        Log("[Error] uploadCentralData failed, %d, %d", ret, status);
        Log("Error, loading central data into sgx fail", log::error);
        return;
    }
    clocker.stop();
    Log("[Service] Call initEnclave success");
}

sgx_status_t PsiService::initEnclave() {
    this->enclave = Enclave::getInstance();
    return this->enclave->createEnclave();
}

uint32_t PsiService::getExtendedEPID_GID() {
    uint32_t extended_epid_group_id = 0;
    int ret = sgx_get_extended_epid_group_id(&extended_epid_group_id);

    if (SGX_SUCCESS != ret) {
        ret = -1;
        Log("[Service] Error, call sgx_get_extended_epid_group_id fail");
        return ret;
    }

    return extended_epid_group_id;
}

int PsiService::remoteAttestationMock(uint8_t *token, uint8_t *sk) {
    Log("[Service] Remote Attestaion Mock start");
    sgx_status_t status;
    int ret = remote_attestation_mock(this->enclave->getID(), &status, token, sk);
    if ((SGX_SUCCESS != ret) || (SGX_SUCCESS != status)) {
        ret = -1;
        Log("[Service] Error, call remote_attestation_mock fail");
        return ret;
    }
    
    return 0;
}

// for parsing curl request
size_t _jsonParseCallback(
    const char* in,
    std::size_t size,
    std::size_t num,
    std::string* out)
{
    const std::size_t totalBytes(size * num);
    out->append(in, totalBytes);
    return totalBytes;
}

// データのロードを担当するよ
int PsiService::loadDataFromBlockChain(
    string transaction_id,
    HistoryData *history
) {
    /* リクエストを送る処理 */

    CURLcode res = CURLE_OK;
    CURL *curl = curl_easy_init();
    curl_easy_setopt( curl, CURLOPT_VERBOSE, 1L );

    // build request
    // url
    std::ostringstream url;
    std::ostringstream params_stream;
    url << "http://13.71.146.191:10000/api/queryusergeodata/";
    params_stream <<  "\{\"selector\":{\"id\":\"" << transaction_id << "\"\}\}";
    url << curl_easy_escape(curl, params_stream.str().c_str(), strlen(params_stream.str().c_str()));
    curl_easy_setopt( curl, CURLOPT_URL, url.str().c_str() );

    // header
    struct curl_slist *headers = NULL;
    headers = curl_slist_append(headers, "Content-Type: application/json");
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 3L); // 3秒しか待たない
    curl_easy_setopt(curl, CURLOPT_PROXY, "proxy.kuins.net:8080");

    // response data
    long httpCode(0);
    std::unique_ptr<std::string> httpData(new std::string());
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, _jsonParseCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, httpData.get());

    // request
    res = curl_easy_perform(curl);
    if (res != CURLE_OK) {
        Log("curl_easy_perform() failed: %s", curl_easy_strerror(res));
        curl_easy_cleanup(curl);
        return -1;
    }
    
    // response
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &httpCode);
    curl_easy_cleanup(curl);

    if (httpCode != 200) return -1;

    /* レスポンスのパース処理 */
    
    // データはなぜかstringでネストされているので注意しましょう
    /* Response Example
    $ curl  -H "Content-type: application/json" 'http://13.71.146.191:10000/api/queryusergeodata/%7B%22selector%22:%7B%22id%22:%221592376965083%22%7D%7D' -x proxy.kuins.net:8080

    {   値がstringになっているので注意
        "response": "[
            {
                \"createTime\":20200617060505,
                \"gps\":\"{ 値がstringになっているで注意2
                    response:[
                        {
                            gps:DUROFAHYtKgdBQLpupzEMn91GKKrJrE7OQFPdatWA==,
                            gcm_tag:WbpT8BIPZRlMyFgaM0u4lA==
                        }
                    ]
                }\",
                \"id\":\"1592376965083\",
                \"objectType\":\"GEODATA\",
                \"ownerId\":\"\",
                \"price\":0,
                \"status\":0,
                \"userId\":\"waseda@android3\"
            }
        ]"
    }

    */

    // curlからの結果を読みとっている
    Json::Value httpJsonValue;
    Json::Reader httpJsonReader;    
    httpJsonReader.parse(*httpData.get(), httpJsonValue);
    std::cout << httpJsonValue << std::endl;
    // 最初の"response"に対応する値を取り出す
    Json::Value responseJsonValue;
    Json::Reader responseJsonReader;
    if (!responseJsonReader.parse(httpJsonValue["response"].asString(), responseJsonValue)) return -1;

    // userIdはここで抜き出す
    uint8_t *user_id;
    int a = ParseUUID(responseJsonValue[0]["userId"].asString(), &user_id);

    memcpy(history->user_id, user_id, UUID_SIZE);
    std::cout << ByteArrayToString(user_id, UUID_SIZE) << std::endl;

    // gpsの中身のstringをパースする
    Json::Value gpsJsonValue;
    Json::Reader gpsJsonReader;

    if (!gpsJsonReader.parse(responseJsonValue[0]["gps"].asString(), gpsJsonValue)) return -1;

    // gpsデータのリストを取り出す
    Json::Value gpsData = gpsJsonValue["response"];

    if (gpsData.size() > 0) {
        for( int i=0; i< gpsData.size(); i++) {
            if (!gpsData[i].isMember("gps") || !gpsData[i].isMember("gcm_tag")) return -3;
            
            uint8_t *geo_buffer;
            int geo_buffer_size = StringToByteArray(Base64decode(gpsData[i]["gps"].asString()), &geo_buffer);
            if (geo_buffer_size % RECORD_SIZE != 0) return -4; // RECORD_SIZEをサーバサイドで意識するのは避けたいが，，，
            
            uint8_t *gcm_tag_buffer;
            StringToByteArray(Base64decode(gpsData[i]["gcm_tag"].asString()), &gcm_tag_buffer);

            history->geo_data_vec.push_back(geo_buffer);
            history->gcm_tag_vec.push_back(gcm_tag_buffer);
            history->size_list_vec.push_back(geo_buffer_size);
        }
    } else {
        Log("[loadDataFromBlockChain] zero size.");
        return -2;
    }
    return 0;
}

int PsiService::judgeContact(
    string user_id,
    uint8_t *session_token,
    uint8_t *encrypted_secret_key,
    uint8_t *secret_key_gcm_tag,
    uint8_t *result,
    uint8_t *result_mac,
    uint8_t *signature
) {
    Log("[Service] judge contact start");
    
    HistoryData history;
    clocker = Clocker("Load data block chain");
    clocker.start();
    int l_ret = loadDataFromBlockChain(user_id, &history);
    if (l_ret < 0) {
        Log("[Service] loadDataFromBlockChain error, %s", l_ret);
        return LOAD_DATA_FROM_BC_ERROR;
    }
    clocker.stop();

    size_t total_size = history.total_geo_data_size();
    uint8_t geo_data_buffer[total_size];
    history.geo_data_as_array(geo_data_buffer);

    size_t gcm_tag_total_size = history.total_gcm_tag_size();
    uint8_t gcm_tag_buffer[gcm_tag_total_size];
    history.gcm_tag_as_array(gcm_tag_buffer);
    
    size_t total_num = history.total_num();
    size_t size_list_buffer[total_num];
    history.size_list_as_array(size_list_buffer, total_num);

    clocker = Clocker("Judge contact");
    clocker.start();
    sgx_status_t status;
    sgx_status_t ret = judge_contact(
        this->enclave->getID(),
        &status,
        session_token,
        encrypted_secret_key,
        secret_key_gcm_tag,
        geo_data_buffer,
        total_size,
        gcm_tag_buffer,
        gcm_tag_total_size,
        size_list_buffer,
        total_num,
        result,
        result_mac,
        signature,
        history.user_id
    );
    
    if (SGX_SUCCESS != ret || SGX_SUCCESS != status) {
        Log("[Service] judge contact failed, %d, %d!", ret, status);
        return (int)status;
    }
    clocker.stop();
    return 0;
}

int PsiService::loadAndStoreInfectedData(
    string user_id,
    uint8_t *session_token,
    uint8_t *encrypted_secret_key,
    uint8_t *secret_key_gcm_tag
){
    Log("[Service] loadAndStoreInfectedData start");
    HistoryData history;
    clocker = Clocker("Load data block chain");
    clocker.start();
    int l_ret = loadDataFromBlockChain(user_id, &history);
    if (l_ret < 0) {
        Log("[Service] loadDataFromBlockChain error, %s", l_ret);
        return LOAD_DATA_FROM_BC_ERROR;
    }
    clocker.stop();

    size_t total_size = history.total_geo_data_size();
    uint8_t geo_data_buffer[total_size];
    history.geo_data_as_array(geo_data_buffer);

    size_t gcm_tag_total_size = history.total_gcm_tag_size();
    uint8_t gcm_tag_buffer[gcm_tag_total_size];
    history.gcm_tag_as_array(gcm_tag_buffer);
    
    size_t total_num = history.total_num();
    size_t size_list_buffer[total_num];
    history.size_list_as_array(size_list_buffer, total_num);

    clocker = Clocker("Store infected data");
    clocker.start();
    sgx_status_t status;
    sgx_status_t ret = store_infected_data(
        this->enclave->getID(),
        &status,
        session_token,
        encrypted_secret_key,
        secret_key_gcm_tag,
        geo_data_buffer,
        total_size,
        gcm_tag_buffer,
        gcm_tag_total_size,
        size_list_buffer,
        total_num
    );
    
    if (SGX_SUCCESS != ret || SGX_SUCCESS != status) {
        Log("[Service] loadAndStoreInfectedData failed, %d, %d!", ret, status);
        return (int)status;
    }
    clocker.stop();

    Log("[Service] store_infected_data success");
    return 0;
}

string PsiService::ClientDataMock(string path) {
    char * filedata = NULL;
    int file_size = 0;
    file_size = ReadFileToBuffer(path, &filedata);

    return string(filedata);
}

int PsiService::getPublicKey(uint8_t *session_token, uint8_t *public_key, uint8_t *gcm_tag) {
    sgx_status_t status;
    sgx_status_t ret = get_public_key(
        this->enclave->getID(),
        &status,
        session_token,
        public_key,
        gcm_tag
    );    
    if (SGX_SUCCESS != ret || SGX_SUCCESS != status) {
        Log("[Service] getPublicKey failed, %d, %d!", ret, status);
        return int(status);
    }

    return 0;  
}