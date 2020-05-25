#include "PsiService.h"

PsiService::PsiService() {
    curl_global_init(CURL_GLOBAL_DEFAULT);
}

PsiService::~PsiService() {
    delete this->enclave;
}

void PsiService::start(string path) {
    Log("[Service] enclave init");

    sgx_status_t ret = this->initEnclave();
    if (SGX_SUCCESS != ret) {
        Log("Error, call initEnclave fail", log::error);
        return;
    }

    sgx_status_t status;
    uint8_t salt[SALT_SIZE];
    ret = initialize(this->enclave->getID(), &status, salt);

    uint8_t * filedata = NULL;
    int file_size = 0;
    file_size = ReadFileToBuffer(path, &filedata);
    if (file_size <= 0) {
        return ;
    }
    
    ret = uploadCentralData(this->enclave->getID(), &status, filedata, file_size);
    if ((SGX_SUCCESS != ret) || (SGX_SUCCESS != status)) {
        Log("[Error] uploadCentralData failed, %d, %d", ret, status);
        Log("Error, loading central data into sgx fail", log::error);
        return;
    }
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
        Log("Error, call sgx_get_extended_epid_group_id fail");
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
        Log("Error, call remote_attestation_mock fail");
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

// params:
//   data: 暗号化されたデータのリストを受け取る
//   
int PsiService::loadDataFromBlockChain(
    string user_id,
    HistoryData *history
) {
    CURLcode res = CURLE_OK;
    CURL *curl = curl_easy_init();
    curl_easy_setopt( curl, CURLOPT_VERBOSE, 1L );

    // build request
    // url
    std::ostringstream url;
    std::ostringstream params_stream;
    url << "http://13.71.146.191:10000/api/queryusergeodata/";
    params_stream <<  "\{\"selector\":{\"userId\":\"" << user_id << "\"\}\}";
    url << curl_easy_escape(curl, params_stream.str().c_str(), strlen(params_stream.str().c_str()));
    curl_easy_setopt( curl, CURLOPT_URL, url.str().c_str() );

    // header
    struct curl_slist *headers = NULL;
    headers = curl_slist_append(headers, "Content-Type: application/json");
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 3L); // 2秒しか待たない
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
    
    Json::Value jsonResponse;
    Json::Reader jsonReader;

    // response例
    // {
    // "response": // なぜかstringで入っている意味が分からない
    //    "[
    //       {"createTime":20200510054040,"gps":"X=100.01, Y=100.02, C=100.03","id":"1589089780627","objectType":"GEODATA","ownerId":"","price":0,"status":0,"userId":"EY100"},{"createTime":20200510054141,"gps":"X=100.01, Y=100.02, C=100.03","id":"1589089841402","objectType":"GEODATA","ownerId":"","price":0,"status":0,"userId":"EY100"},{"createTime":20200510110606,"gps":"X=100.01, Y=100.02, C=100.03","id":"1589109246280","objectType":"GEODATA","ownerId":"","price":0,"status":0,"userId":"EY100"},{"createTime":20200510114545,"gps":"X=100.01, Y=100.02, C=100.03","id":"1589109405481","objectType":"GEODATA","ownerId":"","price":0,"status":0,"userId":"EY100"}
    //    ]"
    // }    
    string responseMock = R"({"response":"[{\"gps\":\"qSuR26wg1Zy4/EDLBwTTOoJ0/VASzdTDTx3TkPcBPn3VJqbsO6ZARrnkkT/XIc8VNWvIgc7bKZJxuwYnbADzMaSELtsiOhB83meUwsFiNTGAxxhU4/f+aKZt9CI0vgDa3SFeMYVlCDw5lBxoUw62DXShylxv9sUoO3e2TD+cc/4BF/ZAtp8V8GRZL4MAz3KjoUuTq7ty5BUlR9QFnaJY2BF6fYc8uweGZT/b7aYgwo/bLYZpJa6yDT3K2GXKvw==\",\"gcm_tag\":\"zBQhMcY0qWZRGd/MCc3MVw==\"},{\"gps\":\"qSuR26wg1Zy4/EDLBwTTOoJ0/VASzdTDTx3TkPcBPn3VJqbsO6ZARrnkkT/XIc8VNWvIgc7bKZJxuwYnbADzMaSELtsiOhB83meUwsFiNTGAxxhU4/f+aKZt9CI0vgDa3SFeMYVlCDw5lBxoUw62DXShylxv9sUoO3e2TD+cc/4BF/ZAtp8V8GRZL4MAz3KjoUuTq7ty5BUlR9QFnaJY2BF6fYc8uweGZT/b7aYgwo/bLYZpJa6yDT3K2GXKvw==\",\"gcm_tag\":\"zBQhMcY0qWZRGd/MCc3MVw==\"},{\"gps\":\"qSuR1qon05m89AXFW0TNd4p471ASzdjASx/WkPBMPX3aNaesb7ZARrnnnzLQIcYfMmqBmcTKYpo3uwYnZwHzNqyEKY9gNwZ4kCyf08FiNT2PwRRc4vOuduo99yJr/gc=\",\"gcm_tag\":\"MGedlhB8i5eUy3J0CILBpw==\"}]"})";
    // if (jsonReader.parse(*httpData.get(), jsonResponse)) {
    if (jsonReader.parse(responseMock, jsonResponse)) {
        Json::Value resJson;
        Json::Reader resReader;
        resReader.parse(jsonResponse["response"].asString(), resJson);
        if (resJson.size() <= 0 ) return -2;
        
        for( int i=0; i< resJson.size(); i++) {
            if (!resJson[i].isMember("gps") || !resJson[i].isMember("gcm_tag")) return -3;
            
            uint8_t *geo_buffer;
            int geo_buffer_size = StringToByteArray(Base64decode(resJson[i]["gps"].asString()), &geo_buffer);
            if (geo_buffer_size % RECORD_SIZE != 0) return -4; // RECORD_SIZEをサーバサイドで意識するのは避けたいが，，，
            
            uint8_t *gcm_tag_buffer;
            StringToByteArray(Base64decode(resJson[i]["gcm_tag"].asString()), &gcm_tag_buffer);

            history->geo_data_vec.push_back(geo_buffer);
            history->gcm_tag_vec.push_back(gcm_tag_buffer);
            history->size_list_vec.push_back(geo_buffer_size);
        }
    } else {
        Log("[loadDataFromBlockChain] invalid data format.");
        return -1;
    }

    return 0;
}

int PsiService::judgeContact(
    string user_id,
    uint8_t *session_token,
    uint8_t *encrypted_secret_key,
    uint8_t *secret_key_gcm_tag,
    uint8_t *risk_level,
    uint8_t *result_mac
) {
    Log("[Service] judge contact start");
    
    HistoryData history;
    int l_ret = loadDataFromBlockChain(user_id, &history);
    if (l_ret < 0) {
        Log("loadDataFromBlockChain error, %s", l_ret);
        return -1;
    }

    size_t total_size = history.total_geo_data_size();
    uint8_t geo_data_buffer[total_size];
    history.geo_data_as_array(geo_data_buffer);

    size_t gcm_tag_total_size = history.total_gcm_tag_size();
    uint8_t gcm_tag_buffer[gcm_tag_total_size];
    history.gcm_tag_as_array(gcm_tag_buffer);
    
    size_t total_num = history.total_num();
    size_t size_list_buffer[total_num];
    history.size_list_as_array(size_list_buffer, total_num);

    
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
        risk_level,
        result_mac
    );
    
    if (SGX_SUCCESS != ret || SGX_SUCCESS != status) {
        Log("[Service] judge contact failed, %d, %d!", ret, status);
        return -1;
    }
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
    int l_ret = loadDataFromBlockChain(user_id, &history);
    if (l_ret < 0) {
        Log("loadDataFromBlockChain error, %s", l_ret);
        return -1;
    }

    size_t total_size = history.total_geo_data_size();
    uint8_t geo_data_buffer[total_size];
    history.geo_data_as_array(geo_data_buffer);

    size_t gcm_tag_total_size = history.total_gcm_tag_size();
    uint8_t gcm_tag_buffer[gcm_tag_total_size];
    history.gcm_tag_as_array(gcm_tag_buffer);
    
    size_t total_num = history.total_num();
    size_t size_list_buffer[total_num];
    history.size_list_as_array(size_list_buffer, total_num);

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
        return -1;
    }

    Log("[Service] store_infected_data success");
    return 0;
}