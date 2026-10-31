// Independent runtime oracle: Qt enumerates/reads its own resources.
// QResource::data() retains the stored-data pointer; QFile reads expanded contents.
// https://doc.qt.io/qt-6/qresource.html#data
#include <QtCore/QCryptographicHash>
#include <QtCore/QDirIterator>
#include <QtCore/QFile>
#include <QtCore/QFileInfo>
#include <QtCore/QJsonArray>
#include <QtCore/QJsonDocument>
#include <QtCore/QJsonObject>
#include <QtCore/QLocale>
#include <QtCore/QResource>
#include <QtCore/QSet>
#ifdef _WIN32
#include <windows.h>
#else
#include <dlfcn.h>
#endif

static const unsigned char *externalStart = nullptr;
static quintptr externalSize = 0;
static QString externalPath;

static QJsonObject owner(const unsigned char *address)
{
    if (externalStart && quintptr(address) >= quintptr(externalStart) &&
        quintptr(address) - quintptr(externalStart) < externalSize)
        return {{"module", externalPath}, {"relative", QString::number(quintptr(address) - quintptr(externalStart))}};
#ifdef _WIN32
    HMODULE module = nullptr;
    if (!GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                          GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                          reinterpret_cast<LPCWSTR>(address), &module)) return {};
    wchar_t path[32768];
    const DWORD size = GetModuleFileNameW(module, path, 32768);
    return {{"module", QFileInfo(QString::fromWCharArray(path, size)).canonicalFilePath()},
            {"relative", QString::number(quintptr(address) - quintptr(module))}};
#else
    Dl_info info = {};
    if (!dladdr(address, &info)) return {};
    return {{"module", QFileInfo(QString::fromLocal8Bit(info.dli_fname)).canonicalFilePath()},
            {"relative", QString::number(quintptr(address) - quintptr(info.dli_fbase))}};
#endif
}

static QJsonObject describe_resource(QResource &resource, const QString &path, const QString &locale)
{
    QJsonObject record = owner(resource.data());
    const QByteArray data = resource.uncompressedData();
    QFile file(path);
    if (locale == "C" && (!file.open(QIODevice::ReadOnly) || file.readAll() != data))
        return {{"error", "QFile/QResource content mismatch"}};
    record["path"] = path.mid(1);
    record["sha256"] = QString::fromLatin1(QCryptographicHash::hash(data, QCryptographicHash::Sha256).toHex());
    record["size"] = double(data.size());
    record["storedSize"] = double(resource.size());
    record["algorithm"] = int(resource.compressionAlgorithm());
    record["locale"] = locale;
    record["language"] = int(QLocale(locale).language());
#if QT_VERSION < QT_VERSION_CHECK(6, 0, 0)
    record["territory"] = int(QLocale(locale).country());
#else
    record["territory"] = int(QLocale(locale).territory());
#endif
    return record;
}

static QJsonArray files()
{
    QJsonArray entries;
    QSet<QString> seen;
    QDirIterator paths(":/", QDirIterator::Subdirectories);
    while (paths.hasNext()) {
        const QString path = paths.next();
        if (!paths.fileInfo().isFile()) continue;
        for (const QString &locale : {QString("C"), QString("de_DE"), QString("ru_RU")}) {
            QResource resource(path, QLocale(locale));
            if (!resource.isValid() || !resource.data()) continue;
            const QString identity = path + QString::number(quintptr(resource.data())) + locale;
            if (seen.contains(identity)) continue;
            seen.insert(identity);
            const auto record = describe_resource(resource, path, locale);
            if (record.contains("error")) return QJsonArray{record};
            entries.append(record);
        }
    }
    return entries;
}

#ifdef _WIN32
#define LAB_EXPORT __declspec(dllexport)
#else
#define LAB_EXPORT __attribute__((visibility("default")))
#endif

#ifdef LAB_DECOY
extern "C" unsigned lab_decoy();
#endif
extern "C" LAB_EXPORT const char *lab_probe()
{
#ifdef LAB_DECOY
    volatile unsigned keep = lab_decoy();
    (void)keep;
#endif
    QLocale::setDefault(QLocale::c());
    static QByteArray output;
    output = QJsonDocument(QJsonObject{{"qtVersion", qVersion()}, {"headersVersion", QT_VERSION_STR}, {"files", files()}}).toJson(QJsonDocument::Compact);
    return output.constData();
}

extern "C" LAB_EXPORT const char *lab_validate_file(const char *path)
{
    QLocale::setDefault(QLocale::c());
    static QByteArray output;
    QFile input(QString::fromLocal8Bit(path));
    if (!input.open(QIODevice::ReadOnly)) return "{\"error\":\"cannot read qres\"}";
    const QByteArray data = input.readAll();
    externalStart = reinterpret_cast<const unsigned char *>(data.constData());
    externalSize = quintptr(data.size());
    externalPath = QFileInfo(input).canonicalFilePath();
    if (!QResource::registerResource(externalStart)) return "{\"error\":\"Qt rejects qres\"}";
    output = QJsonDocument(QJsonObject{{"qtVersion", QT_VERSION_STR}, {"files", files()}}).toJson(QJsonDocument::Compact);
    QResource::unregisterResource(externalStart);
    externalStart = nullptr;
    return output.constData();
}
