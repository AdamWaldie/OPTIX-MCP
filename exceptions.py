class OptixAuthError(Exception):
    def __init__(self, message: str, status_code: int = 401):
        super().__init__(message)
        self.status_code = status_code
        self.message = message


class OptixApiError(Exception):
    def __init__(self, message: str, status_code: int = 502):
        super().__init__(message)
        self.status_code = status_code
        self.message = message


class OptixNotFoundError(OptixApiError):
    def __init__(self, message: str = "Resource not found"):
        super().__init__(message, status_code=404)


class OptixCreditError(OptixApiError):
    def __init__(self, balance: int, required: int, reset_date: str | None = None):
        msg = (
            f"Insufficient OPTIX credits — this operation requires {required} credits "
            f"but your account only has {balance} remaining."
        )
        if reset_date:
            msg += f" Credits reset on {reset_date}."
        msg += " Top up or wait for the next billing cycle, then retry."
        super().__init__(msg, status_code=402)
        self.balance = balance
        self.required = required
        self.reset_date = reset_date
