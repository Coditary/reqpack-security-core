#pragma once

#include <optional>
#include <string>
#include <utility>
#include <variant>

namespace rqp::security {

enum class ErrorCode {
    Ok = 0,
    NotFound,
    InvalidInput,
    ParseFailed,
    StorageFailed,
    NetworkFailed,
    RateLimited,
    BackendUnavailable,
    PolicyBlocked,
    Internal,
};

struct SecurityError {
    ErrorCode code{ErrorCode::Internal};
    std::string message;
    std::string context;

    [[nodiscard]] bool ok() const {
        return code == ErrorCode::Ok;
    }
};

template <typename T> class [[nodiscard]] Result {
    std::variant<T, SecurityError> value_;

  public:
    Result(T value) : value_(std::move(value)) {}
    Result(SecurityError error) : value_(std::move(error)) {}

    [[nodiscard]] bool has_value() const {
        return std::holds_alternative<T>(value_);
    }

    [[nodiscard]] const T& value() const& {
        return std::get<T>(value_);
    }

    [[nodiscard]] T& value() & {
        return std::get<T>(value_);
    }

    [[nodiscard]] T value() && {
        return std::move(std::get<T>(value_));
    }

    [[nodiscard]] const SecurityError& error() const {
        return std::get<SecurityError>(value_);
    }

    [[nodiscard]] explicit operator bool() const {
        return has_value();
    }
};

template <> class [[nodiscard]] Result<void> {
    std::optional<SecurityError> error_;

  public:
    Result() = default;
    explicit Result(SecurityError error) : error_(std::move(error)) {}

    [[nodiscard]] bool has_value() const {
        return !error_.has_value();
    }

    [[nodiscard]] const SecurityError& error() const {
        return error_.value();
    }

    [[nodiscard]] explicit operator bool() const {
        return has_value();
    }
};

inline SecurityError make_error(ErrorCode code, std::string message, std::string context = {}) {
    return SecurityError{.code = code, .message = std::move(message), .context = std::move(context)};
}

} // namespace rqp::security
