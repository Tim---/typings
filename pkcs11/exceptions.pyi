class PKCS11Error(RuntimeError): ...
class AlreadyInitialized(PKCS11Error): ...
class AnotherUserAlreadyLoggedIn(PKCS11Error): ...
class AttributeTypeInvalid(PKCS11Error): ...
class AttributeValueInvalid(PKCS11Error): ...
class AttributeReadOnly(PKCS11Error): ...
class AttributeSensitive(PKCS11Error): ...
class ArgumentsBad(PKCS11Error): ...
class DataInvalid(PKCS11Error): ...
class DataLenRange(PKCS11Error): ...
class DomainParamsInvalid(PKCS11Error): ...
class DeviceError(PKCS11Error): ...
class DeviceMemory(PKCS11Error): ...
class DeviceRemoved(PKCS11Error): ...
class EncryptedDataInvalid(PKCS11Error): ...
class EncryptedDataLenRange(PKCS11Error): ...
class ExceededMaxIterations(PKCS11Error): ...
class FunctionCancelled(PKCS11Error): ...
class FunctionFailed(PKCS11Error): ...
class FunctionRejected(PKCS11Error): ...
class FunctionNotSupported(PKCS11Error): ...
class KeyHandleInvalid(PKCS11Error): ...
class KeyIndigestible(PKCS11Error): ...
class KeyNeeded(PKCS11Error): ...
class KeyNotNeeded(PKCS11Error): ...
class KeyNotWrappable(PKCS11Error): ...
class KeySizeRange(PKCS11Error): ...
class KeyTypeInconsistent(PKCS11Error): ...
class KeyUnextractable(PKCS11Error): ...
class GeneralError(PKCS11Error): ...
class HostMemory(PKCS11Error): ...
class MechanismInvalid(PKCS11Error): ...
class MechanismParamInvalid(PKCS11Error): ...
class MultipleObjectsReturned(PKCS11Error): ...
class MultipleTokensReturned(PKCS11Error): ...
class NoSuchKey(PKCS11Error): ...
class NoSuchToken(PKCS11Error): ...
class ObjectHandleInvalid(PKCS11Error): ...
class OperationActive(PKCS11Error): ...
class OperationNotInitialized(PKCS11Error): ...
class PinExpired(PKCS11Error): ...
class PinIncorrect(PKCS11Error): ...
class PinInvalid(PKCS11Error): ...
class PinLenRange(PKCS11Error): ...
class PinLocked(PKCS11Error): ...
class PinTooWeak(PKCS11Error): ...
class PublicKeyInvalid(PKCS11Error): ...
class RandomNoRNG(PKCS11Error): ...
class RandomSeedNotSupported(PKCS11Error): ...
class SessionClosed(PKCS11Error): ...
class SessionCount(PKCS11Error): ...
class SessionExists(PKCS11Error): ...
class SessionHandleInvalid(PKCS11Error): ...
class SessionReadOnly(PKCS11Error): ...
class SessionReadOnlyExists(PKCS11Error): ...
class SessionReadWriteSOExists(PKCS11Error): ...
class SignatureLenRange(PKCS11Error): ...
class SignatureInvalid(PKCS11Error): ...
class SlotIDInvalid(PKCS11Error): ...
class TemplateIncomplete(PKCS11Error): ...
class TemplateInconsistent(PKCS11Error): ...
class TokenNotPresent(PKCS11Error): ...
class TokenNotRecognised(PKCS11Error): ...
class TokenWriteProtected(PKCS11Error): ...
class UnwrappingKeyHandleInvalid(PKCS11Error): ...
class UnwrappingKeySizeRange(PKCS11Error): ...
class UnwrappingKeyTypeInconsistent(PKCS11Error): ...
class UserAlreadyLoggedIn(PKCS11Error): ...
class UserNotLoggedIn(PKCS11Error): ...
class UserPinNotInitialized(PKCS11Error): ...
class UserTooManyTypes(PKCS11Error): ...
class WrappedKeyInvalid(PKCS11Error): ...
class WrappedKeyLenRange(PKCS11Error): ...
class WrappingKeyHandleInvalid(PKCS11Error): ...
class WrappingKeySizeRange(PKCS11Error): ...
class WrappingKeyTypeInconsistent(PKCS11Error): ...
