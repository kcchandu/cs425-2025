#include <iostream>
#include <string>
#include <thread>
#include <mutex>
#include <unordered_map>
#include <unordered_set>
#include <vector>
#include <sstream>
#include <fstream>
#include <cstring>
#include <cstdlib>
#include <unistd.h>
#include <arpa/inet.h>

#define BUFFER_SIZE 1024

std::mutex cout_mutex;
std::unordered_map<std::string, int> clients; 
std::unordered_map<std::string, std::unordered_set<std::string>> groups; // group_name -> set of usernames
std::unordered_map<int, std::string> client_usernames; // client_socket -> username


void broadcast_message(const std::string &message, int sender_socket) {
    for (const auto &client : clients) {
        if (client.second != sender_socket) {
            send(client.second, message.c_str(), message.size(), 0);
        }
    }
}


void private_message(const std::string &message, const std::string &target_user, int sender_socket) {
    if (clients.find(target_user) != clients.end()) {
        send(clients[target_user], message.c_str(), message.size(), 0);
    } else {
        std::string error_message = "User " + target_user + " not found.\n";
        send(sender_socket, error_message.c_str(), error_message.size(), 0);
    }
}


void group_message(const std::string &message, const std::string &group_name, int sender_socket) {
    if (groups.find(group_name) != groups.end()) {
        for (const auto &member : groups[group_name]) {
            if (clients.find(member) != clients.end() && member != client_usernames[sender_socket]) {
                send(clients[member], message.c_str(), message.size(), 0);
            }
        }
    } else {
        std::string error_message = "Group " + group_name + " does not exist.\n";
        send(sender_socket, error_message.c_str(), error_message.size(), 0);
    }
}


void handle_client(int client_socket) {
    char buffer[BUFFER_SIZE];
    std::string username;


    memset(buffer, 0, BUFFER_SIZE);
    recv(client_socket, buffer, BUFFER_SIZE, 0);
    std::string prompt = "Enter username: ";
    send(client_socket, prompt.c_str(), prompt.size(), 0);
    recv(client_socket, buffer, BUFFER_SIZE, 0);
    username = std::string(buffer);

    // Receive password
    memset(buffer, 0, BUFFER_SIZE);
    prompt = "Enter password: ";
    send(client_socket, prompt.c_str(), prompt.size(), 0);
    recv(client_socket, buffer, BUFFER_SIZE, 0);
    std::string password = std::string(buffer);

    // Authenticate the user
    std::ifstream user_file("users.txt");
    std::string line;
    bool authenticated = false;
    while (std::getline(user_file, line)) {
        size_t pos = line.find(":");
        if (pos != std::string::npos) {
            std::string stored_username = line.substr(0, pos);
            std::string stored_password = line.substr(pos + 1);
            if (stored_username == username && stored_password == password) {
                authenticated = true;
                break;
            }
        }
    }

    // Send authentication result
    if (!authenticated) {
        std::string fail_msg = "Authentication failed.\n";
        send(client_socket, fail_msg.c_str(), fail_msg.size(), 0);
        close(client_socket);
        return;
    }

 
    std::string success_msg = "Welcome to the server, " + username + "!\n";
    send(client_socket, success_msg.c_str(), success_msg.size(), 0);
    clients[username] = client_socket;
    client_usernames[client_socket] = username;

    
    while (true) {
        memset(buffer, 0, BUFFER_SIZE);
        int bytes_received = recv(client_socket, buffer, BUFFER_SIZE, 0);
        if (bytes_received <= 0) {
            std::lock_guard<std::mutex> lock(cout_mutex);
            std::cout << "Client " << username << " disconnected." << std::endl;
            clients.erase(username);
            client_usernames.erase(client_socket);
            close(client_socket);
            break;
        }

        std::string message = std::string(buffer);

       
        if (message == "/exit") {
            std::string exit_msg = "Goodbye, " + username + "!\n";
            send(client_socket, exit_msg.c_str(), exit_msg.size(), 0);
            clients.erase(username);
            client_usernames.erase(client_socket);
            close(client_socket);
            break;
        } else if (message.find("/broadcast ") == 0) {
            broadcast_message("Broadcast message from " + username + ": " + message.substr(11), client_socket);
        } else if (message.find("/msg ") == 0) {
            size_t space_pos = message.find(" ", 5);
            if (space_pos != std::string::npos) {
                std::string target_user = message.substr(5, space_pos - 5);
                private_message("Private message from " + username + ": " + message.substr(space_pos + 1), target_user, client_socket);
            }
        } else if (message.find("/group msg ") == 0) {
            size_t space_pos = message.find(" ", 11);
            if (space_pos != std::string::npos) {
                std::string group_name = message.substr(11, space_pos - 11);
                group_message("Group message from " + username + " in " + group_name + ": " + message.substr(space_pos + 1), group_name, client_socket);
            }
        } else if (message.find("/create group ") == 0) {
            std::string group_name = message.substr(14);
            groups[group_name].insert(username);
            std::string success_msg = "Group " + group_name + " created.\n";
            send(client_socket, success_msg.c_str(), success_msg.size(), 0);
        } else if (message.find("/join group ") == 0) {
            std::string group_name = message.substr(12);
            groups[group_name].insert(username);
            std::string success_msg = "Joined group " + group_name + ".\n";
            send(client_socket, success_msg.c_str(), success_msg.size(), 0);
        } else if (message.find("/leave group ") == 0) {
            std::string group_name = message.substr(13);
            groups[group_name].erase(username);
            std::string success_msg = "Left group " + group_name + ".\n";
            send(client_socket, success_msg.c_str(), success_msg.size(), 0);
        } else {
            std::string error_msg = "Unknown command.\n";
            send(client_socket, error_msg.c_str(), error_msg.size(), 0);
        }
    }
}

int main() {
    int server_socket;
    sockaddr_in server_address{}, client_address{};
    socklen_t client_address_len = sizeof(client_address);

    server_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (server_socket < 0) {
        std::cerr << "Error creating socket." << std::endl;
        return 1;
    }

    server_address.sin_family = AF_INET;
    server_address.sin_port = htons(12345);
    server_address.sin_addr.s_addr = inet_addr("127.0.0.1");

    if (bind(server_socket, (sockaddr*)&server_address, sizeof(server_address)) < 0) {
        std::cerr << "Error binding socket." << std::endl;
        return 1;
    }

    if (listen(server_socket, 5) < 0) {
        std::cerr << "Error listening on socket." << std::endl;
        return 1;
    }

    std::cout << "Server started on port 12345." << std::endl;

    
    while (true) {
        int client_socket = accept(server_socket, (sockaddr*)&client_address, &client_address_len);
        if (client_socket < 0) {
            std::cerr << "Error accepting client connection." << std::endl;
            continue;
        }
        std::cout << "Client connected." << std::endl;
        std::thread client_thread(handle_client, client_socket);
        client_thread.detach(); // Handle each client in a separate thread
    }

    close(server_socket);
    return 0;
}
