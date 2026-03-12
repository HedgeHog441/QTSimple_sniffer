#include "logger.h"

logger& logger::instance(){
    qRegisterMetaType<logger::LogLevel>("LogLevel");
    //qRegisterMetaType<logger::LogLevel>("LogTarget");
    static logger s_instance;
    return s_instance;
}

logger::logger(QObject *parent)
    : QObject{parent}
{}

void logger::log(const QString &msg){
    emit logger::instance().newLog(msg, logger::INFO);
}

void logger::log(const QString &msg, const LogLevel level){
    emit logger::instance().newLog(msg, level);
}

void logger::log(const QString &msg, const QString &prefix){
    emit logger::instance().newLog_pr(msg, prefix);
}

void logger::pc_inc(bool filted){
    emit logger::instance().new_pc_inc(filted);
}

