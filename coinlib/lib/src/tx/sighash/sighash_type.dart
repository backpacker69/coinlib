/// Encapsulates the signature hash type to be used for an input signature.
/// Signatures may sign different output and inputs to allow for transaction
/// modifications. To sign an entire transaction the [all] constructor should be
/// used.
class SigHashType {

  /// Special value representing the default Schnorr behaviour to sign
  /// everything. This is encoded as an absent byte.
  static const schnorrDefaultValue = 0;

  /// Value to sign all outputs
  static const allValue = 1;
  /// Value to sign no outputs
  static const noneValue = 2;
  /// Value to sign the output at the same index as the input
  static const singleValue = 3;
  /// Flag that can be combined with other hash type values to only sign the
  /// input containing the signature
  static const anyOneCanPayFlag = 0x80;
  /// Flag for ANYPREVOUT - allows input to be signed without committing to specific prevout
  static const anyPrevOutFlag = 0x40;
  /// Flag for ANYPREVOUTANYSCRIPT - allows signing without committing to prevout or script
  static const anyPrevOutAnyScriptFlag = 0xC0;

  /// The single byte representation of the sighash type. Use [all], [none],
  /// [single] and [anyOneCanPay] to extract details of the type.
  final int value;

  /// Returns true if the sighash type value is valid.
  static bool validValue(int value) {
    // Standard sighash values (including ANYONECANPAY combinations)
    switch (value) {
      case 1:  // ALL
      case 2:  // NONE
      case 3:  // SINGLE
      case 0x81:  // ALL|ANYONECANPAY
      case 0x82:  // NONE|ANYONECANPAY
      case 0x83:  // SINGLE|ANYONECANPAY
        return true;

      // APO sighash values
      case 0x41:  // ALL|ANYPREVOUT
      case 0x42:  // NONE|ANYPREVOUT
      case 0x43:  // SINGLE|ANYPREVOUT
      case 0xc1:  // ALL|ANYPREVOUTANYSCRIPT
      case 0xc2:  // NONE|ANYPREVOUTANYSCRIPT
      case 0xc3:  // SINGLE|ANYPREVOUTANYSCRIPT
        return true;

      default:
        return false;
    }
  }

  /// Checks if the sighash value is valid and returns an [ArgumentError] if
  /// not.
  static void checkValue(int value) {
    if (!validValue(value)) {
      throw ArgumentError.value(value, "value", "not a valid hash type");
    }
  }

  /// Constructs from the byte representation of the sighash type.
  SigHashType.fromValue(this.value) {
    checkValue(value);
  }

  // Factory constructor for validation
  factory SigHashType.validated(int value) {
    checkValue(value);
    return SigHashType.fromValue(value);
  }

  /// Functions as [SigHashType.all] but produces distinct signatures and is
  /// only acceptable for Taproot Schnorr signatures.
  const SigHashType.schnorrDefault() : value = schnorrDefaultValue;

  /// Sign all of the outputs. If [anyOneCanPay] is true, then only the input
  /// containing the signature will be signed.
  /// If [anyOneCanPay] is false and a Taproot input is being signed, this will
  /// be treated as "SIGHASH_DEFAULT".
  const SigHashType.all({ bool anyOneCanPay = false })
    : value = allValue | (anyOneCanPay ? anyOneCanPayFlag : 0);

  /// Sign no outputs. If [anyOneCanPay] is true, then only the input containing
  /// the signature will be signed.
  const SigHashType.none({ bool anyOneCanPay = false })
    : value = noneValue | (anyOneCanPay ? anyOneCanPayFlag : 0);

  /// Sign the output at the same index as the input. If [anyOneCanPay] is true,
  /// then only the input containing the signature will be signed.
  const SigHashType.single({ bool anyOneCanPay = false })
    : value = singleValue | (anyOneCanPay ? anyOneCanPayFlag : 0);

  // Chainable getters for additional flags
  SigHashType get withAnyOneCanPay => SigHashType.fromValue(value | anyOneCanPayFlag);
  SigHashType get withAnyPrevOut => SigHashType.fromValue(value | anyPrevOutFlag);
  SigHashType get withAnyPrevOutAnyScript => SigHashType.fromValue(value | anyPrevOutAnyScriptFlag);

  /// If this is the default hash type for a Schnorr signature.
  bool get schnorrDefault => value == schnorrDefaultValue;

  /// All outputs shall be signed
  bool get all => value == schnorrDefaultValue || (value & ~(anyOneCanPayFlag | anyPrevOutFlag | anyPrevOutAnyScriptFlag)) == allValue;
  /// No outputs shall be signed
  bool get none => (value & ~(anyOneCanPayFlag | anyPrevOutFlag | anyPrevOutAnyScriptFlag)) == noneValue;
  /// Only the output with the same index as the input shall be signed
  bool get single => (value & ~(anyOneCanPayFlag | anyPrevOutFlag | anyPrevOutAnyScriptFlag)) == singleValue;
  /// Only the input receiving the signature shall be signed
  bool get anyOneCanPay => (value & anyOneCanPayFlag) == anyOneCanPayFlag;
  /// No prevout will be signed
  bool get anyPrevOut => (value & anyPrevOutFlag) == anyPrevOutFlag;
  /// No prevout or output will be signed
  bool get anyPrevOutAnyScript => (value & anyPrevOutAnyScriptFlag) == anyPrevOutAnyScriptFlag;

  @override
  bool operator==(Object other) => other is SigHashType && value == other.value;

  @override
  int get hashCode => value;

}
