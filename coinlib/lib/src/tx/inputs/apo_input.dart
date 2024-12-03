import 'dart:typed_data';
import 'package:coinlib/src/common/serial.dart';
import 'package:coinlib/src/crypto/ec_private_key.dart';
import 'package:coinlib/src/crypto/schnorr_signature.dart';
import 'package:coinlib/src/scripts/script.dart';
import 'package:coinlib/src/tx/sighash/sighash_type.dart';
import 'package:coinlib/src/tx/transaction.dart';
import 'package:coinlib/src/taproot.dart';
import 'package:coinlib/src/tx/output.dart';
import 'input.dart';
import 'raw_input.dart';
import 'input_signature.dart';
import 'taproot_input.dart';

/// Base class for Any-Prevout style Taproot inputs that allow signing without
/// committing to specific previous outputs
abstract class APOInput extends TaprootInput {
  APOInput({
    required super.prevOut,
    required super.witness,
    super.sequence = Input.sequenceFinal,
  });

  @override
  APOInput sign({
    required Transaction tx,
    required int inputN,
    required ECPrivateKey key,
    required List<Output> prevOuts,
    SigHashType hashType = const SigHashType.all(),
  });
}

/// APO input that allows spending with Taproot key path using ANYPREVOUT sighash flag
class APOKeyInput extends APOInput {
  final SchnorrInputSignature? insig;

  @override
  final int? signedSize = 41 + 65; // Same as TaprootKeyInput

  APOKeyInput({
    required super.prevOut,
    this.insig,
    super.sequence = Input.sequenceFinal,
  }) : super(witness: [if (insig != null) insig.bytes]);

  /// Match raw input/witness data to APOKeyInput format
  static APOKeyInput? match(RawInput raw, List<Uint8List> witness) {
    if (raw.scriptSig.isNotEmpty) return null;
    if (witness.length != 1) return null;

    try {
      final sig = SchnorrInputSignature.fromBytes(witness[0]);
      // Verify this is an APO signature
      if (!sig.hashType.anyPrevOut) return null;

      return APOKeyInput(
        prevOut: raw.prevOut,
        insig: sig,
        sequence: raw.sequence,
      );
    } on InvalidInputSignature {
      return null;
    }
  }

  @override
  APOKeyInput sign({
    required Transaction tx,
    required int inputN,
    required ECPrivateKey key,
    required List<Output> prevOuts,
    SigHashType hashType = const SigHashType.all(),
  }) {
    // Force ANYPREVOUT flag
    final apoHashType = SigHashType.validated(
      hashType.value | SigHashType.anyPrevOutFlag
    );

    return addSignature(createInputSignature(
      tx: tx,
      inputN: inputN,
      key: key,
      prevOuts: prevOuts,
      hashType: apoHashType,
    ));
  }

  /// Add/replace signature
  APOKeyInput addSignature(SchnorrInputSignature insig) {
    if (!insig.hashType.anyPrevOut) {
      throw ArgumentError('APOKeyInput requires ANYPREVOUT sighash flag');
    }

    return APOKeyInput(
      prevOut: prevOut,
      insig: insig,
      sequence: sequence,
    );
  }

  @override
  APOKeyInput filterSignatures(bool Function(InputSignature insig) predicate)
    => insig == null || predicate(insig!) ? this : APOKeyInput(
      prevOut: prevOut,
      insig: null,
      sequence: sequence,
    );

  @override
  bool get complete => insig != null;
}

/// APO input that allows spending with Taproot script path using ANYPREVOUTANYSCRIPT
class APOScriptInput extends APOInput {
  final TapLeaf leaf;
  final List<SchnorrInputSignature> sigs;

  APOScriptInput({
    required super.prevOut,
    required this.leaf,
    required Uint8List controlBlock,
    this.sigs = const [],
    super.sequence = Input.sequenceFinal,
  }) : super(
    witness: [
      ...sigs.map((sig) => sig.bytes),
      leaf.script.compiled,
      controlBlock,
    ],
  );

  static APOScriptInput? match(RawInput raw, List<Uint8List> witness) {
    if (raw.scriptSig.isNotEmpty) return null;
    if (witness.length < 2) return null;

    try {
      final controlBlock = witness.last;

      // Verify control block structure
      if (
        controlBlock.length < 33 ||
        (controlBlock.length - 33) % 32 != 0 ||
        (controlBlock.length - 33) ~/ 32 > 128 ||
        controlBlock[0] & 0xfe != TapLeaf.tapscriptVersion
      ) {
        return null;
      }

      final script = Script.decompile(witness[witness.length - 2]);
      final leaf = TapLeaf(script);

      // Parse signatures, keeping only valid ANYPREVOUTANYSCRIPT sigs
      final sigs = witness
        .take(witness.length - 2)
        .map((w) => SchnorrInputSignature.fromBytes(w))
        .where((sig) => sig.hashType.anyPrevOutAnyScript)
        .toList();

      return APOScriptInput(
        prevOut: raw.prevOut,
        leaf: leaf,
        controlBlock: controlBlock,
        sigs: sigs,
        sequence: raw.sequence,
      );
    } on Exception {
      return null;
    }
  }

  @override
  APOScriptInput sign({
    required Transaction tx,
    required int inputN,
    required ECPrivateKey key,
    required List<Output> prevOuts,
    SigHashType hashType = const SigHashType.all(),
  }) {
    // Force ANYPREVOUTANYSCRIPT flag
    final apoHashType = SigHashType.validated(
      hashType.value | SigHashType.anyPrevOutAnyScriptFlag
    );

    return addSignature(createInputSignature(
      tx: tx,
      inputN: inputN,
      key: key,
      prevOuts: [], // Empty since we don't commit to prevouts
      hashType: apoHashType,
      leafHash: leaf.hash,
    ));
  }

  APOScriptInput addSignature(SchnorrInputSignature sig) {
    if (!sig.hashType.anyPrevOutAnyScript) {
      throw ArgumentError(
        'APOScriptInput requires ANYPREVOUTANYSCRIPT sighash flag'
      );
    }

    return APOScriptInput(
      prevOut: prevOut,
      leaf: leaf,
      controlBlock: witness.last,
      sigs: [...sigs, sig],
      sequence: sequence,
    );
  }

  @override
  APOScriptInput filterSignatures(bool Function(InputSignature insig) predicate)
    => APOScriptInput(
      prevOut: prevOut,
      leaf: leaf,
      controlBlock: witness.last,
      sigs: sigs.where(predicate).toList(),
      sequence: sequence,
    );

  @override
  bool get complete => sigs.isNotEmpty;
}
