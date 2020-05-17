App_Cpp_Flags := -std=c++11 -O3
App_Include_Paths := -I.
App_Link_Flags := -lboost_system -lboost_thread -lpthread -lssl -lcrypto

server: Server/Server.cpp
	@$(CXX) Server/Server.cpp -o $@ $(App_Cpp_Flags) $(App_Link_Flags) $(App_Include_Paths)
	@echo "CXX  =>  $@"
	@echo "excecute ./server "

.PHONY: clean
clean:
	@rm -f server
	@echo "DELETE ./server"