#include <cstdio>
#ifdef LAB_QT
#include <QtCore/QCoreApplication>
#endif
extern "C" const char *lab_probe();
extern "C" const char *lab_validate_file(const char *);
int main(int count, char **arguments)
{
#ifdef LAB_QT
    QCoreApplication application(count, arguments);
#endif
    std::puts(count == 2 ? lab_validate_file(arguments[1]) : lab_probe());
    return 0;
}
