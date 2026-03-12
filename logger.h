#ifndef LOGGER_H
#define LOGGER_H

#include <QObject>

class logger : public QObject
{
    Q_OBJECT
public:

    enum LogLevel {INFO, OK, WARNING, ERROR, EMPTY, TAB};
    //enum LogTarget {SERVER, CLIENT, NONE};

    static logger& instance(); // Синглтон

    //static void log(const QString &msg, logger::LogLevel level, logger::LogTarget);

    static void log(const QString &msg);
    static void log(const QString &msg, logger::LogLevel level);
    static void log(const QString &msg, const QString &prefix);

    static void pc_inc(bool filted); // Счетчик пакетов

    //static void logClient(const QString &msg);
    //static void logClient(const QString &msg, logger::LogLevel level);

    logger(const logger&) = delete;
    logger& operator=(const logger&) = delete; // Запираем нафиг синглтон

signals:

    void new_pc_inc(bool filted);

    void newLog(const QString &msg, LogLevel level = INFO); // Сигнал о том, что выводится новый лог
    void newLog_pr(const QString &msg, const QString &prefix);

private:

    explicit logger(QObject *parent = nullptr);

};

#endif // LOGGER_H
