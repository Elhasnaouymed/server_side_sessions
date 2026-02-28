class ServerSideSessionError(Exception):
    message = "Server Side Session Error."

    def __init__(self, message=None):
        if message is not None:
            self.message = message
        super(ServerSideSessionError, self).__init__(self.message)


class ServerSideSessionInitializationError(ServerSideSessionError):
    message = "You must provide all arguments before initializing the instance."


class ServerSideSessionNotInitializedError(ServerSideSessionError):
    message = "Server Side Session has not been initialized!"


class ServerSideSessionCorruptError(ServerSideSessionError):
    message = "Session is corrupt or you provided different encryption key."


class ServerSideSessionAlreadyInitialized(ServerSideSessionError):
    message = "Server Side Session is already initialized."


class ServerSideSessionWriteError(ServerSideSessionError):
    message = "Session Can not be written to disk."