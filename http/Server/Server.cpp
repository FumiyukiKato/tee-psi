// ex1.cpp
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
    .run();
}