// In test/helpers/bitcoin_rpc.dart

import 'dart:convert';
import 'dart:io';
import 'package:http/http.dart' as http;

class BitcoinRPC {
  final String host;
  final int port;
  final String user;
  final String password;
  int _id = 0;

  BitcoinRPC({
    this.host = 'localhost',
    this.port = 19999,
    this.user = 'ololo',
    this.password = 'lolol',
  });

  Future<dynamic> _call(String method, [List<dynamic> params = const []]) async {
    final client = http.Client();
    try {
      final response = await client.post(
        Uri.parse('http://$host:$port'),
        headers: {
          'content-type': 'application/json',
          'Authorization': 'Basic ' +
            base64Encode(utf8.encode('$user:$password')),
        },
        body: jsonEncode({
          'jsonrpc': '2.0',
          'id': _id++,
          'method': method,
          'params': params,
        }),
      ).timeout(Duration(minutes: 30)); // Changed from default 30 seconds to 30 minutes

      final result = jsonDecode(response.body);
      if (result['error'] != null) {
        throw Exception(result['error']);
      }
      return result['result'];
    } finally {
      client.close();
    }
  }

  Future<String> generateToAddress(int blocks, String address) async {
    final result = await _call('generatetoaddress', [blocks, address, 100000000]);
    return result[0].toString();
  }

  Future<dynamic> getRawTransaction(String txid, [bool verbose = false]) async {
    return _call('getrawtransaction', [txid, verbose]);
  }

  Future<String> getNewAddress() async {
    final result = await _call('getnewaddress');
    return result.toString();
  }

  Future<String> sendRawTransaction(String txHex) async {
    final result = await _call('sendrawtransaction', [txHex]);
    return result.toString();
  }

  // Helper for getting confirmed balance at address
  Future<BigInt> getAddressBalance(String address) async {
    final utxos = await _call('scantxoutset', ['start', ['addr($address)']]);
    return BigInt.from((utxos['total_amount'] * 100000000).round());
  }

  // Helper to get unspent outputs for address
  Future<List<Map<String, dynamic>>> getAddressUnspent(String address) async {
    final result = await _call('scantxoutset', ['start', ['addr($address)']]);
    return List<Map<String, dynamic>>.from(result['unspents']);
  }
}
