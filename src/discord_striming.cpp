#include <obs-module.h>
#include <obs-frontend-api.h>

#include <QAction>
#include <QCheckBox>
#include <QCryptographicHash>
#include <QDialog>
#include <QDialogButtonBox>
#include <QDesktopServices>
#include <QFormLayout>
#include <QHBoxLayout>
#include <QJsonDocument>
#include <QJsonObject>
#include <QLabel>
#include <QMessageBox>
#include <QNetworkAccessManager>
#include <QNetworkReply>
#include <QNetworkRequest>
#include <QPointer>
#include <QPushButton>
#include <QRandomGenerator>
#include <QSignalBlocker>
#include <QTimer>
#include <QUrl>
#include <QUrlQuery>
#include <QWidget>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cctype>
#include <cstdio>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <functional>
#include <memory>
#include <mutex>
#include <optional>
#include <sstream>
#include <string>
#include <vector>

#ifdef _WIN32
#include <windows.h>
#include <wincred.h>
#elif defined(__APPLE__)
#import <Foundation/Foundation.h>
#include <Security/Security.h>
#include <cerrno>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#else
#include <cerrno>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#endif

OBS_DECLARE_MODULE()

namespace {

constexpr uint32_t kHandshake = 0;
constexpr uint32_t kFrame = 1;
constexpr char kConfigFile[] = "discord-striming.json";
constexpr char kDiscordApplicationId[] = "1545043766132604978";
constexpr char kOAuthClientId[] = "obs-discord-striming";
constexpr char kOAuthBaseUrl[] = "https://strim.ing/api/oauth";
constexpr char kKeychainService[] = "ing.strim.obs-discord-striming";
constexpr char kKeychainAccount[] = "stream-metadata-refresh-token";

struct Settings {
	bool enabled = true;
	std::string application_id = kDiscordApplicationId;
};

std::mutex settings_mutex;
Settings settings;
QAction *activity_toggle_action = nullptr;
std::atomic<int64_t> stream_started_at{0};
std::atomic<uint64_t> nonce{0};
struct StreamMetadata {
	std::string title;
	std::string category;
	std::string watch_url;
	std::string image_url;
	std::string image_text;
	std::string account_name;
	std::string account_username;
};
std::mutex metadata_mutex;
std::optional<StreamMetadata> stream_metadata;
QNetworkAccessManager *oauth_network = nullptr;
QTimer *metadata_refresh_timer = nullptr;
QTimer *oauth_poll_timer = nullptr;
std::string oauth_device_code;
std::string oauth_verifier;
QWidget *oauth_parent = nullptr;
QPointer<QLabel> account_status_label;
QPointer<QPushButton> connect_account_button;
QPointer<QPushButton> disconnect_account_button;

std::string json_escape(const std::string &value)
{
	std::ostringstream out;
	for (const unsigned char ch : value) {
		switch (ch) {
		case '\\': out << "\\\\"; break;
		case '\"': out << "\\\""; break;
		case '\b': out << "\\b"; break;
		case '\f': out << "\\f"; break;
		case '\n': out << "\\n"; break;
		case '\r': out << "\\r"; break;
		case '\t': out << "\\t"; break;
		default:
			if (ch < 0x20) {
				char buffer[7];
				snprintf(buffer, sizeof(buffer), "\\u%04x", ch);
				out << buffer;
			} else {
				out << ch;
			}
		}
	}
	return out.str();
}

bool is_strim_whip_destination()
{
	obs_service_t *service = obs_frontend_get_streaming_service();
	if (!service)
		return false;

	const char *protocol = obs_service_get_protocol(service);
	if (!protocol || std::strcmp(protocol, "WHIP") != 0)
		return false;

	obs_data_t *service_settings = obs_service_get_settings(service);
	if (!service_settings)
		return false;
	std::string server = obs_data_get_string(service_settings, "server");
	obs_data_release(service_settings);

	std::transform(server.begin(), server.end(), server.begin(), [](unsigned char ch) {
		return static_cast<char>(std::tolower(ch));
	});
	const size_t scheme_end = server.find("://");
	if (scheme_end == std::string::npos)
		return false;
	const size_t host_start = scheme_end + 3;
	const size_t host_end = server.find_first_of("/?#", host_start);
	std::string host = server.substr(host_start, host_end - host_start);
	const size_t credentials_end = host.rfind('@');
	if (credentials_end != std::string::npos)
		host.erase(0, credentials_end + 1);
	const size_t port_start = host.find(':');
	if (port_start != std::string::npos)
		host.erase(port_start);

	return host == "strim.ing";
}

bool valid_application_id(const std::string &id)
{
	if (id.empty())
		return false;
	for (const unsigned char ch : id) {
		if (ch < '0' || ch > '9')
			return false;
	}
	return true;
}

std::string subject_label(const std::string &subject)
{
	if (subject == "WATCH_PARTY") return "Watch party";
	if (subject == "GAME") return "Gaming";
	if (subject == "MOVIE") return "Movies";
	if (subject == "MUSIC") return "Music";
	if (subject == "CODING") return "Coding";
	if (subject == "ART") return "Art";
	if (subject == "VIDEOS") return "Videos";
	if (subject == "TALKING") return "Just chatting";
	if (subject == "OTHER") return "Other";
	return subject;
}

std::string random_urlsafe(size_t bytes)
{
	QByteArray data(static_cast<int>(bytes), Qt::Uninitialized);
#ifdef __APPLE__
	if (SecRandomCopyBytes(kSecRandomDefault, bytes,
		reinterpret_cast<uint8_t *>(data.data())) != errSecSuccess)
		return {};
#else
	for (int offset = 0; offset < data.size(); offset += static_cast<int>(sizeof(quint32))) {
		const quint32 value = QRandomGenerator::system()->generate();
		std::memcpy(data.data() + offset, &value,
			std::min<int>(static_cast<int>(sizeof(value)), data.size() - offset));
	}
#endif
	return data.toBase64(QByteArray::Base64UrlEncoding | QByteArray::OmitTrailingEquals).toStdString();
}

std::optional<std::string> refresh_token_from_keychain()
{
#ifdef __APPLE__
	UInt32 length = 0;
	void *data = nullptr;
	SecKeychainItemRef item = nullptr;
	const OSStatus status = SecKeychainFindGenericPassword(
		nullptr, static_cast<UInt32>(std::strlen(kKeychainService)), kKeychainService,
		static_cast<UInt32>(std::strlen(kKeychainAccount)), kKeychainAccount, &length, &data, &item);
	if (status != errSecSuccess)
		return std::nullopt;
	std::string token(static_cast<const char *>(data), length);
	SecKeychainItemFreeContent(nullptr, data);
	CFRelease(item);
	return token;
#elif defined(_WIN32)
	PCREDENTIALW credential = nullptr;
	if (!CredReadW(L"ing.strim.obs-discord-striming/stream-metadata-refresh-token",
		CRED_TYPE_GENERIC, 0, &credential))
		return std::nullopt;
	std::string token(reinterpret_cast<const char *>(credential->CredentialBlob),
		credential->CredentialBlobSize);
	CredFree(credential);
	return token;
#else
	return std::nullopt;
#endif
}

bool save_refresh_token_to_keychain(const std::string &token)
{
#ifdef __APPLE__
	if (token.empty())
		return false;
	UInt32 existing_length = 0;
	void *existing_data = nullptr;
	SecKeychainItemRef item = nullptr;
	const OSStatus found = SecKeychainFindGenericPassword(
		nullptr, static_cast<UInt32>(std::strlen(kKeychainService)), kKeychainService,
		static_cast<UInt32>(std::strlen(kKeychainAccount)), kKeychainAccount,
		&existing_length, &existing_data, &item);
	if (found == errSecSuccess) {
		SecKeychainItemFreeContent(nullptr, existing_data);
		const OSStatus updated = SecKeychainItemModifyAttributesAndData(
			item, nullptr, static_cast<UInt32>(token.size()), token.data());
		CFRelease(item);
		return updated == errSecSuccess;
	}
	return SecKeychainAddGenericPassword(
		nullptr, static_cast<UInt32>(std::strlen(kKeychainService)), kKeychainService,
		static_cast<UInt32>(std::strlen(kKeychainAccount)), kKeychainAccount,
		static_cast<UInt32>(token.size()), token.data(), nullptr) == errSecSuccess;
#elif defined(_WIN32)
	if (token.empty() || token.size() > CRED_MAX_CREDENTIAL_BLOB_SIZE)
		return false;
	CREDENTIALW credential{};
	credential.Type = CRED_TYPE_GENERIC;
	credential.TargetName = const_cast<LPWSTR>(
		L"ing.strim.obs-discord-striming/stream-metadata-refresh-token");
	credential.CredentialBlobSize = static_cast<DWORD>(token.size());
	credential.CredentialBlob = reinterpret_cast<LPBYTE>(const_cast<char *>(token.data()));
	credential.Persist = CRED_PERSIST_LOCAL_MACHINE;
	credential.UserName = const_cast<LPWSTR>(L"strim.ing OBS Discord Activity");
	return CredWriteW(&credential, 0) != 0;
#else
	(void)token;
	return false;
#endif
}

void remove_refresh_token_from_keychain()
{
#ifdef __APPLE__
	UInt32 length = 0;
	void *data = nullptr;
	SecKeychainItemRef item = nullptr;
	if (SecKeychainFindGenericPassword(
		nullptr, static_cast<UInt32>(std::strlen(kKeychainService)), kKeychainService,
		static_cast<UInt32>(std::strlen(kKeychainAccount)), kKeychainAccount,
		&length, &data, &item) == errSecSuccess) {
		SecKeychainItemFreeContent(nullptr, data);
		SecKeychainItemDelete(item);
		CFRelease(item);
	}
#elif defined(_WIN32)
	CredDeleteW(L"ing.strim.obs-discord-striming/stream-metadata-refresh-token",
		CRED_TYPE_GENERIC, 0);
#endif
}

void update_account_controls(const std::string &account_name = {}, const std::string &account_username = {})
{
	const bool connected = refresh_token_from_keychain().has_value();
	if (connect_account_button)
		connect_account_button->setVisible(!connected);
	if (disconnect_account_button)
		disconnect_account_button->setVisible(connected);
	if (!account_status_label)
		return;
	if (!connected) {
		account_status_label->setText("No strim account connected");
		return;
	}
	if (!account_name.empty()) {
		std::string message = "Connected as " + account_name;
		if (!account_username.empty())
			message += " (@" + account_username + ")";
		account_status_label->setText(QString::fromStdString(message));
		return;
	}
	account_status_label->setText("Connected to strim.ing");
}

QNetworkRequest oauth_request(const char *path)
{
	QNetworkRequest request(QUrl(QString::fromUtf8(kOAuthBaseUrl) + QString::fromUtf8(path)));
	request.setHeader(QNetworkRequest::ContentTypeHeader, "application/x-www-form-urlencoded");
	request.setRawHeader("Accept", "application/json");
	return request;
}

QJsonObject reply_object(QNetworkReply *reply)
{
	const QJsonDocument document = QJsonDocument::fromJson(reply->readAll());
	return document.isObject() ? document.object() : QJsonObject{};
}

using OAuthCompletion = std::function<void(bool, const QJsonObject &)>;

void deliver_oauth_response(bool succeeded, const QByteArray &payload, OAuthCompletion completion)
{
	const QJsonDocument document = QJsonDocument::fromJson(payload);
	const QJsonObject body = document.isObject() ? document.object() : QJsonObject{};
	QMetaObject::invokeMethod(oauth_network, [succeeded, body, completion = std::move(completion)] {
		completion(succeeded, body);
	}, Qt::QueuedConnection);
}

void oauth_post(const char *path, const QUrlQuery &form, OAuthCompletion completion)
{
#ifdef __APPLE__
	@autoreleasepool {
		const QByteArray url_bytes = (QString::fromUtf8(kOAuthBaseUrl) + QString::fromUtf8(path)).toUtf8();
		const QByteArray form_bytes = form.query(QUrl::FullyEncoded).toUtf8();
		NSURL *url = [NSURL URLWithString:[NSString stringWithUTF8String:url_bytes.constData()]];
		NSMutableURLRequest *request = [NSMutableURLRequest requestWithURL:url];
		request.HTTPMethod = @"POST";
		[request setValue:@"application/x-www-form-urlencoded" forHTTPHeaderField:@"Content-Type"];
		[request setValue:@"application/json" forHTTPHeaderField:@"Accept"];
		request.HTTPBody = [NSData dataWithBytes:form_bytes.constData() length:form_bytes.size()];
		NSURLSessionDataTask *task = [[NSURLSession sharedSession]
			dataTaskWithRequest:request
			completionHandler:^(NSData *data, NSURLResponse *response, NSError *error) {
				const auto *http = [response isKindOfClass:[NSHTTPURLResponse class]]
					? static_cast<NSHTTPURLResponse *>(response)
					: nil;
				const bool succeeded = error == nil && http && http.statusCode >= 200 && http.statusCode < 300;
				const QByteArray payload = data
					? QByteArray(static_cast<const char *>(data.bytes), static_cast<int>(data.length))
					: QByteArray{};
				deliver_oauth_response(succeeded, payload, std::move(completion));
			}];
		[task resume];
	}
#else
	auto *reply = oauth_network->post(oauth_request(path), form.query(QUrl::FullyEncoded).toUtf8());
	QObject::connect(reply, &QNetworkReply::finished, [reply, completion = std::move(completion)] {
		const QJsonObject body = reply_object(reply);
		const bool succeeded = reply->error() == QNetworkReply::NoError;
		reply->deleteLater();
		completion(succeeded, body);
	});
#endif
}

void oauth_get(const char *path, const QString &access_token, OAuthCompletion completion)
{
#ifdef __APPLE__
	@autoreleasepool {
		const QByteArray url_bytes = (QString::fromUtf8(kOAuthBaseUrl) + QString::fromUtf8(path)).toUtf8();
		NSURL *url = [NSURL URLWithString:[NSString stringWithUTF8String:url_bytes.constData()]];
		NSMutableURLRequest *request = [NSMutableURLRequest requestWithURL:url];
		[request setValue:@"application/json" forHTTPHeaderField:@"Accept"];
		const QByteArray authorization = "Bearer " + access_token.toUtf8();
		[request setValue:[NSString stringWithUTF8String:authorization.constData()] forHTTPHeaderField:@"Authorization"];
		NSURLSessionDataTask *task = [[NSURLSession sharedSession]
			dataTaskWithRequest:request
			completionHandler:^(NSData *data, NSURLResponse *response, NSError *error) {
				const auto *http = [response isKindOfClass:[NSHTTPURLResponse class]]
					? static_cast<NSHTTPURLResponse *>(response)
					: nil;
				const bool succeeded = error == nil && http && http.statusCode >= 200 && http.statusCode < 300;
				const QByteArray payload = data
					? QByteArray(static_cast<const char *>(data.bytes), static_cast<int>(data.length))
					: QByteArray{};
				deliver_oauth_response(succeeded, payload, std::move(completion));
			}];
		[task resume];
	}
#else
	QNetworkRequest request(QUrl(QString::fromUtf8(kOAuthBaseUrl) + QString::fromUtf8(path)));
	request.setRawHeader("Accept", "application/json");
	request.setRawHeader("Authorization", "Bearer " + access_token.toUtf8());
	auto *reply = oauth_network->get(request);
	QObject::connect(reply, &QNetworkReply::finished, [reply, completion = std::move(completion)] {
		const QJsonObject body = reply_object(reply);
		const bool succeeded = reply->error() == QNetworkReply::NoError;
		reply->deleteLater();
		completion(succeeded, body);
	});
#endif
}

class DiscordIpc {
public:
	~DiscordIpc() { close(); }

	bool connect(const std::string &application_id)
	{
		if (connected_ && application_id == application_id_)
			return true;
		close();
		if (!open_transport())
			return false;

		const std::string handshake =
			"{\"v\":1,\"client_id\":\"" + json_escape(application_id) + "\"}";
		if (!write_frame(kHandshake, handshake)) {
			close();
			return false;
		}


		uint32_t opcode = 0;
		std::string response;
		if (!read_frame(opcode, response) || opcode != kFrame ||
		    response.find("\"evt\":\"READY\"") == std::string::npos) {
			close();
			return false;
		}

		application_id_ = application_id;
		connected_ = true;
		return true;
	}

	bool set_activity(const std::string &activity)
	{
		if (!connected_)
			return false;
		const auto current_nonce = std::to_string(++nonce);
		const std::string payload =
			"{\"cmd\":\"SET_ACTIVITY\",\"nonce\":\"" + current_nonce +
			"\",\"args\":{\"pid\":" + std::to_string(process_id()) +
			",\"activity\":" + activity + "}}";
		if (!write_frame(kFrame, payload))
			return false;

		// Discord answers SET_ACTIVITY with the same nonce. Waiting for that
		// acknowledgement lets us distinguish a successful socket write from a
		// rejected activity (for example, an invalid button URL).
		for (int attempt = 0; attempt < 4; ++attempt) {
			uint32_t opcode = 0;
			std::string response;
			if (!read_frame(opcode, response) || opcode != kFrame)
				return false;
			if (response.find("\"nonce\":\"" + current_nonce + "\"") == std::string::npos)
				continue;
			return response.find("\"cmd\":\"SET_ACTIVITY\"") != std::string::npos &&
			       response.find("\"evt\":\"ERROR\"") == std::string::npos;
		}
		return false;
	}

	void close()
	{
#ifdef _WIN32
		if (pipe_ != INVALID_HANDLE_VALUE) {
			CloseHandle(pipe_);
			pipe_ = INVALID_HANDLE_VALUE;
		}
#else
		if (socket_ >= 0) {
			::close(socket_);
			socket_ = -1;
		}
#endif
		connected_ = false;
		application_id_.clear();
	}

private:
#ifdef _WIN32
	HANDLE pipe_ = INVALID_HANDLE_VALUE;
#else
	int socket_ = -1;
#endif
	bool connected_ = false;
	std::string application_id_;

	static uint32_t process_id()
	{
#ifdef _WIN32
		return GetCurrentProcessId();
#else
		return static_cast<uint32_t>(getpid());
#endif
	}

	bool open_transport()
	{
#ifdef _WIN32
		for (int index = 0; index < 10; ++index) {
			const std::string name = "\\\\?\\pipe\\discord-ipc-" + std::to_string(index);
			pipe_ = CreateFileA(name.c_str(), GENERIC_READ | GENERIC_WRITE, 0, nullptr,
				OPEN_EXISTING, 0, nullptr);
			if (pipe_ != INVALID_HANDLE_VALUE)
				return true;
		}
		return false;
#else
		std::vector<std::string> roots;
		if (const char *runtime_dir = std::getenv("XDG_RUNTIME_DIR"))
			roots.emplace_back(runtime_dir);
		if (const char *tmp_dir = std::getenv("TMPDIR"))
			roots.emplace_back(tmp_dir);
		if (const char *tmp_dir = std::getenv("TMP"))
			roots.emplace_back(tmp_dir);
		if (const char *temp_dir = std::getenv("TEMP"))
			roots.emplace_back(temp_dir);
		roots.emplace_back("/tmp");

		for (const auto &root : roots) {
			for (int index = 0; index < 10; ++index) {
				const std::string path = root + "/discord-ipc-" + std::to_string(index);
				const int candidate = ::socket(AF_UNIX, SOCK_STREAM, 0);
				if (candidate < 0)
					continue;
				sockaddr_un address{};
				if (path.size() >= sizeof(address.sun_path)) {
					::close(candidate);
					continue;
				}
				address.sun_family = AF_UNIX;
				std::strncpy(address.sun_path, path.c_str(), sizeof(address.sun_path) - 1);
				if (::connect(candidate, reinterpret_cast<sockaddr *>(&address), sizeof(address)) == 0) {
					timeval timeout{};
					timeout.tv_sec = 2;
					setsockopt(candidate, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
					socket_ = candidate;
					return true;
				}
				::close(candidate);
			}
		}
		return false;
#endif
	}

	bool write_frame(uint32_t opcode, const std::string &payload)
	{
		const uint32_t length = static_cast<uint32_t>(payload.size());
		uint8_t header[8];
		for (int byte = 0; byte < 4; ++byte) {
			header[byte] = static_cast<uint8_t>(opcode >> (byte * 8));
			header[byte + 4] = static_cast<uint8_t>(length >> (byte * 8));
		}
		return write_all(header, sizeof(header)) &&
			write_all(reinterpret_cast<const uint8_t *>(payload.data()), payload.size());
	}

	bool write_all(const uint8_t *data, size_t length)
	{
		size_t offset = 0;
		while (offset < length) {
#ifdef _WIN32
			DWORD written = 0;
			if (!WriteFile(pipe_, data + offset, static_cast<DWORD>(length - offset), &written, nullptr) || written == 0) {
				connected_ = false;
				return false;
			}
			offset += written;
#else
			const ssize_t written = ::send(socket_, data + offset, length - offset, MSG_NOSIGNAL);
			if (written <= 0) {
				if (written < 0 && errno == EINTR)
					continue;
				connected_ = false;
				return false;
			}
			offset += static_cast<size_t>(written);
#endif
		}
		return true;
	}

	bool read_frame(uint32_t &opcode, std::string &payload)
	{
		uint8_t header[8];
		if (!read_all(header, sizeof(header)))
			return false;

		opcode = 0;
		uint32_t length = 0;
		for (int byte = 0; byte < 4; ++byte) {
			opcode |= static_cast<uint32_t>(header[byte]) << (byte * 8);
			length |= static_cast<uint32_t>(header[byte + 4]) << (byte * 8);
		}
		if (length > 64 * 1024) {
			connected_ = false;
			return false;
		}

		payload.assign(length, '\0');
		return length == 0 || read_all(reinterpret_cast<uint8_t *>(payload.data()), length);
	}

	bool read_all(uint8_t *data, size_t length)
	{
		size_t offset = 0;
		while (offset < length) {
#ifdef _WIN32
			DWORD received = 0;
			if (!ReadFile(pipe_, data + offset, static_cast<DWORD>(length - offset), &received, nullptr) || received == 0) {
				connected_ = false;
				return false;
			}
			offset += received;
#else
			const ssize_t received = ::recv(socket_, data + offset, length - offset, 0);
			if (received <= 0) {
				if (received < 0 && errno == EINTR)
					continue;
				connected_ = false;
				return false;
			}
			offset += static_cast<size_t>(received);
#endif
		}
		return true;
	}
};

DiscordIpc discord;
std::mutex discord_mutex;

Settings current_settings()
{
	std::lock_guard<std::mutex> lock(settings_mutex);
	return settings;
}

void clear_activity()
{
	std::lock_guard<std::mutex> lock(discord_mutex);
	if (discord.set_activity("null"))
		blog(LOG_INFO, "[strim Discord] Cleared Discord activity");
	discord.close();
}

std::string activity_for()
{
	const int64_t started = stream_started_at.load();
	std::optional<StreamMetadata> metadata;
	{
		std::lock_guard<std::mutex> lock(metadata_mutex);
		metadata = stream_metadata;
	}
	const std::string title = metadata ? metadata->title : "";
	const std::string category = metadata ? metadata->category : "";
	const std::string watch_url = metadata ? metadata->watch_url : "";
	std::ostringstream activity;
	// Discord's current IPC API reserves Streaming (type 1) for clients that
	// are not allowed to set it through SET_ACTIVITY. A normal Rich Presence
	// activity with explicit streaming details is accepted by the local API.
	const std::string details = title.empty()
		? "Streaming on strim.ing"
		: "Streaming " + title + " on strim.ing";
	activity << "{\"type\":0,\"details\":\"" << json_escape(details) << "\"";
	if (!category.empty())
		activity << ",\"state\":\"" << json_escape(subject_label(category) + " · Live on strim.ing") << "\"";
	if (started > 0)
		activity << ",\"timestamps\":{\"start\":" << started << "}";
	if (metadata && !metadata->image_url.empty()) {
		activity << ",\"assets\":{\"large_image\":\""
			 << json_escape(metadata->image_url) << "\",\"large_text\":\""
			 << json_escape(metadata->image_text) << "\"}";
	}
	if (!watch_url.empty()) {
		activity << ",\"buttons\":[{\"label\":\"Watch on strim.ing\",\"url\":\""
			 << json_escape(watch_url) << "\"}]";
	}
	activity << "}";
	return activity.str();
}

void publish_activity()
{
	if (!is_strim_whip_destination()) {
		blog(LOG_INFO, "[strim Discord] Not publishing activity: OBS is not streaming to a strim.ing WHIP destination.");
		return;
	}
	const Settings value = current_settings();
	if (!value.enabled || !valid_application_id(value.application_id))
		return;

	std::lock_guard<std::mutex> lock(discord_mutex);
	if (!discord.connect(value.application_id)) {
		blog(LOG_WARNING, "[strim Discord] Discord desktop IPC is unavailable; start Discord, then restart or update the stream.");
		return;
	}
	if (!discord.set_activity(activity_for())) {
		// Discord may have restarted. Reconnect once so a normal restart does not
		// leave the stream without presence until the next OBS event.
		if (discord.connect(value.application_id) && discord.set_activity(activity_for()))
			blog(LOG_INFO, "[strim Discord] Discord activity published after reconnect");
		else
			blog(LOG_WARNING, "[strim Discord] Discord rejected the activity or did not respond");
	} else {
		blog(LOG_INFO, "[strim Discord] Discord activity published");
	}
}

void fetch_stream_metadata(const QString &access_token)
{
	if (!oauth_network || access_token.isEmpty())
		return;
	oauth_get("/stream", access_token, [] (bool succeeded, const QJsonObject &body) {
		if (!succeeded) {
			blog(LOG_WARNING, "[strim Discord] Could not refresh strim stream metadata");
			return;
		}
		StreamMetadata updated;
		updated.title = body.value("title").toString().toStdString();
		updated.category = body.value("subject").toString().toStdString();
		updated.watch_url = body.value("watchUrl").toString().toStdString();
		updated.image_url = body.value("imageUrl").toString().toStdString();
		updated.image_text = body.value("imageText").toString().toStdString();
		updated.account_name = body.value("accountName").toString().toStdString();
		updated.account_username = body.value("accountUsername").toString().toStdString();
		{
			std::lock_guard<std::mutex> lock(metadata_mutex);
			stream_metadata = updated;
		}
		update_account_controls(updated.account_name, updated.account_username);
		if (obs_frontend_streaming_active() && is_strim_whip_destination())
			publish_activity();
	});
}

void refresh_stream_metadata()
{
	if (!oauth_network)
		return;
	const auto refresh_token = refresh_token_from_keychain();
	if (!refresh_token)
		return;
	QUrlQuery form;
	form.addQueryItem("grant_type", "refresh_token");
	form.addQueryItem("client_id", QString::fromUtf8(kOAuthClientId));
	form.addQueryItem("refresh_token", QString::fromStdString(*refresh_token));
	oauth_post("/token", form, [] (bool succeeded, const QJsonObject &body) {
		const QString access_token = body.value("access_token").toString();
		const QString refresh_token = body.value("refresh_token").toString();
		if (!succeeded || access_token.isEmpty() || refresh_token.isEmpty()) {
			blog(LOG_WARNING, "[strim Discord] strim account authorization needs to be reconnected");
			return;
		}
		if (!save_refresh_token_to_keychain(refresh_token.toStdString())) {
			blog(LOG_WARNING, "[strim Discord] Could not save the strim authorization in macOS Keychain");
			return;
		}
		fetch_stream_metadata(access_token);
	});
}

void poll_oauth_device_authorization()
{
	if (!oauth_network || oauth_device_code.empty() || oauth_verifier.empty())
		return;
	QUrlQuery form;
	form.addQueryItem("grant_type", "urn:ietf:params:oauth:grant-type:device_code");
	form.addQueryItem("client_id", QString::fromUtf8(kOAuthClientId));
	form.addQueryItem("device_code", QString::fromStdString(oauth_device_code));
	form.addQueryItem("code_verifier", QString::fromStdString(oauth_verifier));
	oauth_post("/token", form, [] (bool succeeded, const QJsonObject &body) {
		if (!succeeded) {
			// The expected response until the user completes the browser consent is
			// authorization_pending. Other errors end this attempt without logging
			// a token or code.
			if (body.value("message").toString() == "authorization_pending")
				return;
			if (oauth_poll_timer)
				oauth_poll_timer->stop();
			oauth_device_code.clear();
			oauth_verifier.clear();
			QMessageBox::warning(oauth_parent, "strim.ing account", "Authorization expired or was denied. Please try again.");
			return;
		}
		const QString refresh_token = body.value("refresh_token").toString();
		if (refresh_token.isEmpty() || !save_refresh_token_to_keychain(refresh_token.toStdString())) {
			QMessageBox::warning(oauth_parent, "strim.ing account", "Could not save authorization in macOS Keychain.");
			return;
		}
		if (oauth_poll_timer)
			oauth_poll_timer->stop();
		oauth_device_code.clear();
		oauth_verifier.clear();
		update_account_controls();
		QMessageBox::information(oauth_parent, "strim.ing account", "Connected. OBS will now update Discord with your stream title and category.");
		refresh_stream_metadata();
	});
}

void begin_oauth_device_authorization(QWidget *parent)
{
	if (!oauth_network)
		return;
	const std::string verifier = random_urlsafe(48);
	if (verifier.empty()) {
		QMessageBox::warning(parent, "strim.ing account", "Could not create secure authorization data.");
		return;
	}
	const QByteArray challenge = QCryptographicHash::hash(
		QByteArray::fromStdString(verifier), QCryptographicHash::Sha256)
		.toBase64(QByteArray::Base64UrlEncoding | QByteArray::OmitTrailingEquals);
	QUrlQuery form;
	form.addQueryItem("client_id", QString::fromUtf8(kOAuthClientId));
	form.addQueryItem("scope", "stream.read");
	form.addQueryItem("code_challenge", QString::fromUtf8(challenge));
	form.addQueryItem("code_challenge_method", "S256");
	oauth_post("/device/authorize", form, [verifier, parent] (bool succeeded, const QJsonObject &body) {
		const QString device_code = body.value("device_code").toString();
		const QUrl verification_url(body.value("verification_uri_complete").toString());
		if (!succeeded || device_code.isEmpty() || !verification_url.isValid()) {
			QMessageBox::warning(parent, "strim.ing account", "Could not start strim authorization. Check your internet connection and try again.");
			return;
		}
		oauth_parent = parent;
		oauth_device_code = device_code.toStdString();
		oauth_verifier = verifier;
		QDesktopServices::openUrl(verification_url);
		if (oauth_poll_timer)
			oauth_poll_timer->start(5000);
		QMessageBox::information(parent, "strim.ing account", "Finish the authorization in your browser. OBS will connect automatically when you approve it.");
	});
}

std::string config_path()
{
	char *path = obs_module_config_path(kConfigFile);
	if (!path)
		return {};
	std::string result(path);
	bfree(path);
	return result;
}

void load_settings()
{
	obs_data_t *data = obs_data_create_from_json_file(config_path().c_str());
	if (!data)
		data = obs_data_create();
	obs_data_set_default_bool(data, "enabled", true);

	Settings loaded;
	loaded.enabled = obs_data_get_bool(data, "enabled");
	loaded.application_id = kDiscordApplicationId;
	{
		std::lock_guard<std::mutex> lock(settings_mutex);
		settings = std::move(loaded);
	}
	obs_data_release(data);
}

void save_settings(const Settings &value)
{
	obs_data_t *data = obs_data_create();
	obs_data_set_bool(data, "enabled", value.enabled);
	obs_data_save_json(data, config_path().c_str());
	obs_data_release(data);
	{
		std::lock_guard<std::mutex> lock(settings_mutex);
		settings = value;
	}
}

void synchronize_toggle(const Settings &value)
{
	if (!activity_toggle_action)
		return;
	const QSignalBlocker block(activity_toggle_action);
	activity_toggle_action->setChecked(value.enabled);
}

void apply_settings(const Settings &value)
{
	const bool was_enabled = current_settings().enabled;
	save_settings(value);
	synchronize_toggle(value);
	if (!value.enabled && was_enabled)
		clear_activity();
	else if (value.enabled && obs_frontend_streaming_active())
		publish_activity();
}

void on_frontend_event(enum obs_frontend_event event, void *)
{
	switch (event) {
	case OBS_FRONTEND_EVENT_STREAMING_STARTED:
		if (!is_strim_whip_destination()) {
			blog(LOG_INFO, "[strim Discord] Streaming started on a non-strim destination; Discord activity remains off.");
			break;
		}
		stream_started_at.store(std::chrono::duration_cast<std::chrono::seconds>(
			std::chrono::system_clock::now().time_since_epoch()).count());
		publish_activity();
		if (metadata_refresh_timer)
			metadata_refresh_timer->start();
		refresh_stream_metadata();
		break;
	case OBS_FRONTEND_EVENT_STREAMING_STOPPED:
		stream_started_at.store(0);
		if (metadata_refresh_timer)
			metadata_refresh_timer->stop();
		{
			std::lock_guard<std::mutex> lock(metadata_mutex);
			stream_metadata.reset();
		}
		clear_activity();
		break;
	case OBS_FRONTEND_EVENT_EXIT:
		clear_activity();
		break;
	default:
		break;
	}
}

void show_settings_dialog()
{
	auto *parent = static_cast<QWidget *>(obs_frontend_get_main_window());
	auto *dialog = new QDialog(parent);
	dialog->setAttribute(Qt::WA_DeleteOnClose);
	dialog->setWindowTitle("strim.ing Discord Activity");
	dialog->setMinimumWidth(520);

	const Settings initial = current_settings();
	auto *layout = new QFormLayout(dialog);
	auto *enabled = new QCheckBox("Enable Discord streaming activity", dialog);
	enabled->setChecked(initial.enabled);
	layout->addRow(enabled);
	layout->addRow("Discord application", new QLabel("strim.ing", dialog));
	layout->addRow(new QLabel("Without a connected account, Discord only shows “Streaming on strim.ing”.", dialog));
	layout->addRow(new QLabel("Connect your account to share its live title, category, and watch link.", dialog));
	auto *account_buttons = new QWidget(dialog);
	auto *account_layout = new QHBoxLayout(account_buttons);
	account_layout->setContentsMargins(0, 0, 0, 0);
	auto *account_status = new QLabel(account_buttons);
	auto *connect_account = new QPushButton("Connect strim account…", account_buttons);
	auto *disconnect_account = new QPushButton("Disconnect", account_buttons);
	account_status_label = account_status;
	connect_account_button = connect_account;
	disconnect_account_button = disconnect_account;
	update_account_controls();
	account_layout->addWidget(account_status);
	account_layout->addStretch();
	account_layout->addWidget(connect_account);
	account_layout->addWidget(disconnect_account);
	layout->addRow("Automatic metadata", account_buttons);

	auto *buttons = new QDialogButtonBox(QDialogButtonBox::Save | QDialogButtonBox::Cancel, dialog);
	layout->addRow(buttons);
	QObject::connect(buttons, &QDialogButtonBox::rejected, dialog, &QDialog::reject);
	QObject::connect(connect_account, &QPushButton::clicked, dialog, [dialog] { begin_oauth_device_authorization(dialog); });
	QObject::connect(disconnect_account, &QPushButton::clicked, dialog, [] {
		remove_refresh_token_from_keychain();
		std::lock_guard<std::mutex> lock(metadata_mutex);
		stream_metadata.reset();
		update_account_controls();
	});
	QObject::connect(buttons, &QDialogButtonBox::accepted, dialog, [dialog, enabled] {
		Settings updated;
		updated.enabled = enabled->isChecked();
		updated.application_id = kDiscordApplicationId;
		apply_settings(updated);
		dialog->accept();
	});
	dialog->show();
	// Refresh immediately so an existing connection shows its account name
	// without requiring the user to start a stream first.
	refresh_stream_metadata();
}

} // namespace

bool obs_module_load(void)
{
	load_settings();
	auto *main_window = static_cast<QWidget *>(obs_frontend_get_main_window());
	oauth_network = new QNetworkAccessManager(main_window);
	metadata_refresh_timer = new QTimer(main_window);
	metadata_refresh_timer->setInterval(60 * 1000);
	QObject::connect(metadata_refresh_timer, &QTimer::timeout, [] { refresh_stream_metadata(); });
	oauth_poll_timer = new QTimer(main_window);
	QObject::connect(oauth_poll_timer, &QTimer::timeout, [] { poll_oauth_device_authorization(); });
	obs_frontend_add_event_callback(on_frontend_event, nullptr);
	auto *action = static_cast<QAction *>(
		obs_frontend_add_tools_menu_qaction("strim.ing Discord Activity…"));
	QObject::connect(action, &QAction::triggered, [] { show_settings_dialog(); });

	activity_toggle_action = static_cast<QAction *>(
		obs_frontend_add_tools_menu_qaction("Share streaming activity on Discord"));
	activity_toggle_action->setCheckable(true);
	activity_toggle_action->setChecked(current_settings().enabled);
	QObject::connect(activity_toggle_action, &QAction::toggled, [](bool enabled) {
		Settings updated = current_settings();
		updated.enabled = enabled;
		apply_settings(updated);
	});
	blog(LOG_INFO, "[strim Discord] Module loaded");
	return true;
}

void obs_module_unload(void)
{
	obs_frontend_remove_event_callback(on_frontend_event, nullptr);
	clear_activity();
}

const char *obs_module_name(void)
{
	return "strim.ing Discord Activity";
}

const char *obs_module_description(void)
{
	return "Publishes a Discord Rich Presence activity while OBS is streaming on strim.ing.";
}
