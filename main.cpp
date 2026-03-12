#include "widget.h"

#include <QApplication>

int main(int argc, char *argv[])
{

    qputenv("QT_LOGGING_RULES", "qt.qpa.wayland = false");

    QApplication a(argc, argv);
    Widget w;
    w.show();
    return a.exec();
}
