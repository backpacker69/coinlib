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
        prevOuts: prevOuts,
        hashType: const SigHashType.all().withAnyPrevOut
      );

      expect(
        apoHasher.hash,
        isNot(equals(standardHasher.hash))
      );
    });
  });
}
