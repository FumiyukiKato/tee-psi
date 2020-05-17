#define CROW_ENABLE_SSL
#include "crow_all.h"

int main()
{
  crow::SimpleApp app;

  CROW_ROUTE(app, "/")
  ([]{
    return "Hello, world!";
  });

  app
    .port(8080)
    .ssl_file("../server.crt", "../server.key") // curl --cacert path/to/server.crt https://localhost:50001
    .run();
}