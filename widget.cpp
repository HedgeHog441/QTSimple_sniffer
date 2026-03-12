#include "widget.h"
#include "./ui_widget.h"

Widget::Widget(QWidget *parent)
    : QWidget(parent)
    , ui(new Ui::Widget)
{
    ui->setupUi(this);
    QObject::connect(&logger::instance(), &logger::newLog, this, &Widget::handleLog);
    QObject::connect(&logger::instance(), &logger::newLog_pr, this, &Widget::handleLog_pr);

    QObject::connect(&logger::instance(), &logger::new_pc_inc, this, &Widget::handlePC_inc);

    _Sniffer = new sniffer();
    _Sniffer->scanInterface();

    std::vector<std::string> iface = _Sniffer->getInterfaces();
    for(auto i : iface){
        ui->interface_choose->addItem(QString::fromStdString(i));
    }
}

Widget::~Widget()
{
    delete(_Sniffer);
    delete ui;
}

void Widget::handleLog(const QString &msg, logger::LogLevel level){

    QString color = "gray";
    QString prefix = "[*]";

    if(level == logger::OK){
        color = "green";
        prefix = "[OK]";
    }
    else if(level == logger::WARNING){
        color = "orange";
        prefix = "[WARN]";
    }else if(level == logger::ERROR){
        color = "red";
        prefix = "[ERR]";
    }else if(level == logger::EMPTY){
        QString HTML_msg = QString(" ");
        ui->logTable->appendHtml(HTML_msg);
        return;
    }
    else if(level == logger::TAB){
        color = "black";
        prefix = "[*]";
    }

    QString HTML_msg = QString("<font color = %1>%2</font> <font color = gray>%3</font>")
                           .arg(color, prefix, msg);
    ui->logTable->appendHtml(HTML_msg);
}

void Widget::handleLog_pr(const QString &msg, const QString &prefix_){

    QString color = "gray";
    QString prefix = "[" + prefix_ + "]";

    QString HTML_msg = QString("<font color = %1>%2</font> <font color = gray>%3</font>")
                           .arg(color, prefix, msg);
    ui->logTable->appendHtml(HTML_msg);
}

void Widget::handlePC_inc(bool filted){
    _Sniffer->pc++;
    ui->packet_count_label->setText(QString::number(_Sniffer->pc));

    if(filted){
        _Sniffer->pc_f++;
        ui->filter_packet_count_label->setText(QString::number(_Sniffer->pc_f));
    }
}

void Widget::on_startButton_clicked()
{

    if(ui->interface_choose->currentText() == '-'){
        logger::log("Выберите интерфейс", logger::WARNING);
        return;
    }
    ui->startButton->setEnabled(0);
    ui->stopButton->setEnabled(1);

    ui->filters_Button->setEnabled(0);
    //
    _Sniffer->start();

}


void Widget::on_stopButton_clicked()
{
    ui->stopButton->setEnabled(0);
    ui->startButton->setEnabled(1);

    ui->filters_Button->setEnabled(1);
    //
    _Sniffer->stop();

}


void Widget::on_interface_choose_currentTextChanged(const QString &arg1)
{
    _Sniffer->setInterface(arg1);
}



void Widget::on_filters_Button_clicked()
{
    // КНОПКА ФИЛЬТРОВ
    sniffer::Filters &data = _Sniffer->filters;

    data.ARP = ui->ARP_box->isChecked();
    data.IPv4 = ui->IPv4_box->isChecked();
    data.IPv6 = ui->IPv6_box->isChecked();
    data.TCP = ui->TCP_box->isChecked();
    data.UDP = ui->UDP_box->isChecked();

}


void Widget::on_resetinfo_Button_clicked()
{
    _Sniffer->pc = 0;
    _Sniffer->pc_f = 0;
    ui->packet_count_label->setText(QString::number(_Sniffer->pc));
    ui->filter_packet_count_label->setText(QString::number(_Sniffer->pc_f));
}

