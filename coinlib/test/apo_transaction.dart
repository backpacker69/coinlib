import 'dart:typed_data';
import 'package:test/test.dart';
import 'package:coinlib/coinlib.dart';
import 'common/coin_rpc.dart';

void main() {
  loadCoinlib();

  // Constants
  const BIP118_PUBKEY_PREFIX = 0x01;

  test(
    'can spend individual UTXOs using APO anyprevoutanyscript signature',
    () async {
      final rpc = BitcoinRPC();

      // Create key from WIF and derive address
      final wif = WIF.fromString("cTaX33gn9nqVDLdNTTNBDzZH8JmFgLDvFzymiiCKsKH41Cp7kqAf");
      final internalKey = wif.privkey;

      // Create APO pubkey by prepending 0x01 to x-coordinate
      final apoPubkeyBytes = Uint8List(33);
      apoPubkeyBytes[0] = BIP118_PUBKEY_PREFIX;
      apoPubkeyBytes.setRange(1, 33, internalKey.pubkey.x);

      // Create a tapscript (e.g., a simple public key verification script)
      final scriptPubKey = internalKey.pubkey;
      final tapscript = Script([
        ScriptPushData(apoPubkeyBytes),
        ScriptOpCode.fromName("CHECKSIG"),
      ]);

      // Create a tap leaf containing the script
      final leaf = TapLeaf(tapscript);

      // Create the taproot structure with the internal key and script tree
      final taproot = Taproot(
        internalKey: internalKey.pubkey,
        mast: leaf, // For a single script, the leaf is the entire tree
      );

      // Create the address
      final addressTR = P2TRAddress.fromTweakedKey(
        taproot.tweakedKey,
        hrp: Network.testnet.bech32Hrp,
      );

      print('Address: ${addressTR.toString()}');

      // 2. Now verify the configuration

      // Decode the address back from string
      final decodedAddress = Address.fromString(
        addressTR.toString(),
        Network.testnet,
      ) as P2TRAddress;

      // Get the program from the address
      final program = decodedAddress.program;
      if (program is! P2TR) {
        throw Exception('Not a P2TR program');
      }

      // Verify the tweaked public key matches
      final expectedTweakedKey = taproot.tweakedKey;
      if (!bytesEqual(program.tweakedKey.data, expectedTweakedKey.data)) {
        throw Exception('Tweaked key mismatch');
      }
      print('Tweaked key verified ✓');

      // Verify we can create a matching control block for our script
      final controlBlock = taproot.controlBlockForLeaf(leaf);

      // Create a test input to verify script path
      final testInput = TaprootScriptInput.fromTaprootLeaf(
        prevOut: OutPoint(Uint8List(32), 0),
        taproot: taproot,
        leaf: leaf,
      );

      // Verify control block matches
      if (!bytesEqual(testInput.controlBlock, controlBlock)) {
        throw Exception('Control block mismatch');
      }
      print('Control block verified ✓');

      // Verify script matches
      if (!bytesEqual(leaf.script.compiled, tapscript.compiled)) {
        throw Exception('Script mismatch');
      }
      print('Script verified ✓');

      // Verify leaf hash
      final leafHash = TapLeaf(tapscript).hash;
      final expectedLeafHash = leaf.hash;
      if (!bytesEqual(leafHash, expectedLeafHash)) {
        throw Exception('Leaf hash mismatch');
      }
      print('Leaf hash verified ✓');

      print('\nVerification Details:');
      print('Internal Key: ${bytesToHex(internalKey.pubkey.data)}');
      print('APO Public Key: ${bytesToHex(apoPubkeyBytes)}');
      print('Tweaked Key: ${bytesToHex(taproot.tweakedKey.data)}');
      print('Script Hash: ${bytesToHex(leafHash)}');
      print('Control Block: ${bytesToHex(controlBlock)}');

      final address = addressTR.toString();
      print('Using address: $address');

      // Get UTXOs for the address
      final utxos = await rpc.getAddressUnspent(address);
      expect(utxos.length, greaterThanOrEqualTo(1), reason: 'Need at least 1 UTXO');

      final destProgram1 = Address.fromString(address, Network.testnet).program;

      // Create common prevOut for signature based on first UTXO
      final prevOut = Output.fromProgram(
        BigInt.from((utxos[0]['amount'] * 1000000).round()),
        P2TR.fromTaproot(taproot)
      );

      // Create first transaction spending first UTXO
      var tx1 = Transaction(
        version: 3,
        inputs: [
          // Create initial unsigned input
          TaprootScriptInput.fromTaprootLeaf(
            prevOut: OutPoint(
                  Uint8List.fromList(hexToBytes(utxos[0]['txid']).reversed.toList()),
                  utxos[0]['vout']
                ),
            taproot: taproot,
            leaf: leaf,
          ),
        ],
        outputs: [
          Output.fromProgram(
            BigInt.from((utxos[0]['amount'] * 1000000).round()) - BigInt.from(10000),
            destProgram1
          )
        ]
      );

      final tweakedKey = taproot.tweakPrivateKey(internalKey);

      // Create signature for the tapscript
      final input = tx1.inputs.first as TaprootScriptInput;
      final signature = input.createScriptSignature(
        tx: tx1,
        inputN: 0,
        key: internalKey,
        prevOuts: [prevOut],
        hashType: SigHashType.fromValue(0xc1), // Use ALL|ANYPREVOUTANYSCRIPT sighash
      );

      // Update the input with the signature
      final signedTx = tx1.replaceInput(
        input.updateStack([signature.bytes]),
        0,
      );

      print('Signed Transaction Hex: ${bytesToHex(signedTx.toBytes())}');
      print('Signature Hash Type: 0x${signature.hashType.value.toRadixString(16)}');

      // Broadcast transactions
      final tx1Hex = bytesToHex(signedTx.toBytes());

      print('\nTransaction 1 hex:');
      print(tx1Hex);

      final sentTx1 = await rpc.sendRawTransaction(tx1Hex);

      print('accepted ${sentTx1}');
    },
    timeout: Timeout(Duration(minutes: 30)),
  );
}
