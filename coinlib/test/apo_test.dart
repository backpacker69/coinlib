import 'dart:typed_data';
import 'package:test/test.dart';
import 'package:coinlib/coinlib.dart';

void main() {
  loadCoinlib();

  group('SigHashType APO Tests', () {
    test('should correctly combine sighash flags', () {
      final hashType = const SigHashType.all().withAnyPrevOut;
      expect(hashType.anyPrevOut, isTrue);
      expect(hashType.all, isTrue);
      expect(hashType.anyOneCanPay, isFalse);

      final combined = hashType.withAnyOneCanPay;
      expect(combined.anyPrevOut, isTrue);
      expect(combined.anyOneCanPay, isTrue);
      expect(combined.all, isTrue);
    });

    test('should validate sighash values', () {
      expect(
        () => SigHashType.validated(SigHashType.allValue | SigHashType.anyPrevOutFlag),
        returnsNormally
      );

      expect(
        () => SigHashType.validated(0xFF),
        throwsArgumentError
      );
    });
  });

  group('TaprootSignatureHasher APO Tests', () {
    late Transaction tx;
    late ECPrivateKey key;
    late List<Output> prevOuts;

    setUp(() {
      key = ECPrivateKey.generate();
      final taproot = Taproot(internalKey: key.pubkey);
      final output = Output.fromProgram(
        BigInt.from(10000),
        P2TR.fromTaproot(taproot)
      );
      prevOuts = List.filled(1, output);

      tx = Transaction(
        version: 2,
        inputs: [
          TaprootKeyInput(
            prevOut: OutPoint(Uint8List(32), 0),
          ),
        ],
        outputs: [output],
      );
    });

    test('should compute different hashes for APO vs non-APO', () {
      final standardHasher = TaprootSignatureHasher(
        tx: tx,
        inputN: 0,
        prevOuts: prevOuts,
        hashType: const SigHashType.all()
      );

      final apoHasher = TaprootSignatureHasher(
        tx: tx,
        inputN: 0,
        prevOuts: [], // Empty list is valid for APO
        hashType: const SigHashType.all().withAnyPrevOut
      );

      expect(
        apoHasher.hash,
        isNot(equals(standardHasher.hash))
      );
    });
  });

  group('APO Input Tests', () {
    late ECPrivateKey key;
    late Transaction tx;
    late OutPoint prevOut;
    late List<Output> prevOuts;
    late Output output;
    late Taproot taproot;

    setUp(() {
      key = ECPrivateKey.generate();
      prevOut = OutPoint(Uint8List(32), 0);

      // Create taproot output
      taproot = Taproot(internalKey: key.pubkey);
      output = Output.fromProgram(
        BigInt.from(10000),
        P2TR.fromTaproot(taproot)
      );

      // For APO tests, we need one prevOut per input 
      prevOuts = List.filled(1, output);

      tx = Transaction(
        version: 2,
        inputs: [APOKeyInput(prevOut: prevOut)],
        outputs: [output],
      );
    });

    test('should create and sign APOKeyInput', () {
      final input = APOKeyInput(prevOut: prevOut);

      final signed = input.sign(
        tx: tx,
        inputN: 0,
        key: taproot.tweakPrivateKey(key),
        prevOuts: prevOuts,
      );

      expect(signed.complete, isTrue);
      expect(signed.insig!.hashType.anyPrevOut, isTrue);
    });

    test('should serialize and deserialize APO inputs', () {
      final input = APOKeyInput(prevOut: prevOut);
      final signed = input.sign(
        tx: tx,
        inputN: 0,
        key: taproot.tweakPrivateKey(key),
        prevOuts: prevOuts,
      );

      final serialized = Transaction(
        version: 2,
        inputs: [signed],
        outputs: [output]
      );

      final bytes = serialized.toBytes();
      final deserialized = Transaction.fromBytes(bytes);

      expect(
        deserialized.inputs.first,
        isA<APOKeyInput>()
      );
    });
  });
}
