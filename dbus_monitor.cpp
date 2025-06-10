#include <dbus/dbus.h>
#include <iostream>
#include <fstream>
#include <string>
#include <cstring>
#include <cstdlib>
#include <unistd.h>
#include <sys/types.h>   // <-- для umask
#include <sys/stat.h>    // <-- для umask
void log_to_file(const std::string& message) {
    std::ofstream log_file("/var/log/dbus_monitor.log", std::ios::app);
    if (log_file.is_open()) {
        log_file << message << std::endl;
        log_file.close();
    } else {
        std::cerr << "Не удалось открыть файл для логирования." << std::endl;
    }
}

void daemonize() {
    pid_t pid = fork();
    if (pid < 0) {
        std::cerr << "Ошибка при создании процесса-демона." << std::endl;
        exit(EXIT_FAILURE);
    }
    if (pid > 0) {
        exit(EXIT_SUCCESS); // Родитель завершается
    }

    if (setsid() < 0) {
        std::cerr << "Ошибка при создании новой сессии." << std::endl;
        exit(EXIT_FAILURE);
    }

    if (chdir("/") < 0) {
        std::cerr << "Ошибка при смене директории." << std::endl;
        exit(EXIT_FAILURE);
    }

    umask(0);

    fclose(stdin);
    fclose(stdout);
    fclose(stderr);
}

int main() {
    daemonize();

    DBusError dbus_error;
    DBusConnection* dbus_conn = nullptr;
    DBusMessage* dbus_msg = nullptr;

    dbus_error_init(&dbus_error);

    dbus_conn = dbus_bus_get(DBUS_BUS_SESSION, &dbus_error);
    if (!dbus_conn) {
        log_to_file(std::string("Ошибка подключения к D-Bus: ") + dbus_error.message);
        dbus_error_free(&dbus_error);
        return 1;
    }
    log_to_file("Успешно подключено к D-Bus");

    dbus_bus_add_match(dbus_conn, "type='signal'", &dbus_error);
    if (dbus_error_is_set(&dbus_error)) {
        log_to_file(std::string("Ошибка установки фильтра: ") + dbus_error.message);
        dbus_error_free(&dbus_error);
        return 1;
    }
    log_to_file("Фильтр сигналов успешно установлен.");

    while (true) {
        dbus_connection_read_write(dbus_conn, 0);
        dbus_msg = dbus_connection_pop_message(dbus_conn);

        if (dbus_msg == nullptr) {
            sleep(1);
            continue;
        }

        if (dbus_message_get_type(dbus_msg) == DBUS_MESSAGE_TYPE_SIGNAL) {
            std::string interface = dbus_message_get_interface(dbus_msg);
            std::string path = dbus_message_get_path(dbus_msg);
            std::string member = dbus_message_get_member(dbus_msg);

            std::string log_msg = "Получен сигнал: Интерфейс=" + interface +
                                  ", Путь=" + path +
                                  ", Метод=" + member;
            log_to_file(log_msg);
        }

        dbus_message_unref(dbus_msg);
    }

    dbus_connection_unref(dbus_conn);
    return 0;
}
