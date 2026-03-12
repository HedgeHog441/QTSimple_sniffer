#ifndef WIDGET_H
#define WIDGET_H
#include "./ui_widget.h"
#include <QWidget>
#include "logger.h"
#include "sniffer.h"

QT_BEGIN_NAMESPACE
namespace Ui {
class Widget;
}
QT_END_NAMESPACE

class Widget : public QWidget
{
    Q_OBJECT

public:
    Widget(QWidget *parent = nullptr);
    ~Widget();

private slots:

    void on_startButton_clicked();

    void on_stopButton_clicked();

    void on_interface_choose_currentTextChanged(const QString &arg1);

    void on_filters_Button_clicked();

    void on_resetinfo_Button_clicked();

private:
    Ui::Widget *ui;

    sniffer* _Sniffer = nullptr;

    void handleLog(const QString &msg, logger::LogLevel level);
    void handleLog_pr(const QString &msg, const QString &prefix_);

    void handlePC_inc(bool filted);
};
#endif // WIDGET_H
