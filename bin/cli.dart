import 'package:cli/auth_client.dart';
import 'package:cli/cli.dart';

import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';

import 'package:pointycastle/asn1.dart';
import 'package:pointycastle/export.dart';

import 'package:basic_utils/basic_utils.dart';

var cborKey =
    'pQECAyYgASFYIIcEZtPD-t7SgrBCqo8DmkzK-5hPRC7Agr9-4w2Egc3EIlggArnWSfgKmTTjWiOvtNu9Ck7jJDJpVJvff7CX_xQhzbk=';

Future<void> main() async {
  final Base64Codec base64 = const Base64Codec();

  // the private key
  ECPrivateKey? privateKey;

  final String curve = 'prime256v1';
  final akp = CryptoUtils.generateEcKeyPair(curve: curve);

  final pubKey = akp.publicKey as ECPublicKey;
  privateKey = akp.privateKey as ECPrivateKey;

  final url = 'My URL string...';
  //Convert the URL string to Uint8List
  final bytes = utf8.encode(url);

  final pemFullKey = CryptoUtils.encodeEcPrivateKeyToPem(privateKey);
  final pemPub = CryptoUtils.encodeEcPublicKeyToPem(pubKey);
  print('pemFullKey.length = ${pemFullKey.length}');
  final b64FullKey = base64.encode(utf8.encode(pemFullKey));
  print(utf8.decode(base64.decode(b64FullKey)) == pemFullKey);
  print('b64FullKey.length = ${b64FullKey.length}');
  print('pemFullKey= $pemFullKey');
  print('pemPub.length = ${pemPub.length}');
  var ok = testSignature2(privateKey, pemPub, bytes);
  print('==> ok = $ok');

  ok = testSignature(pemFullKey, pemPub, bytes);
  print('==> ok = $ok');

  final comb = '$pemFullKey\n$pemPub';

  print(comb);
  ok = testSignature3(comb, bytes);
  print('merge => ok = $ok');

  final calVal = calculate();
  print(calVal);
  
  exec(["register", "tmp-man"]);

  return;
  //privateKey.d.

  // some bytes to sign
  //final bytes = Uint8List(0);

  // a suitable random number generator - create it just once and reuse
  final rand = Random.secure();
  final fortunaPrng = FortunaRandom()
    ..seed(KeyParameter(Uint8List.fromList(List<int>.generate(
      32,
      (_) => rand.nextInt(256),
    ))));

  // the ECDSA signer using SHA-256
  final signer = ECDSASigner(SHA256Digest())
    ..init(
      true,
      ParametersWithRandom(
        PrivateKeyParameter(privateKey),
        fortunaPrng,
      ),
    );

  // sign the bytes
  final ecSignature = signer.generateSignature(bytes) as ECSignature;

  // encode the two signature values in a common format
  // hopefully this is what the server expects
  final _ = ASN1Sequence(elements: [
    ASN1Integer(ecSignature.r),
    ASN1Integer(ecSignature.s),
  ]).encode();

  // and finally base 64 encode it
//final signature = base64UrlEncode(encoded);

  ECSignature sig =
      CryptoUtils.ecSign(privateKey, bytes, algorithmName: 'SHA-256/ECDSA');
  //final pem = CryptoUtils.encodeEcPublicKeyToPem(pubKey);
  final pemPriv = CryptoUtils.encodeEcPrivateKeyToPem(privateKey);
  print('pemPriv: $pemPriv');
  final privData = privateKey.d!;

  final b64PrivData = base64.encode(CryptoUtils.i2osp(privData));
  
  print('=== privData in b64 ====');
  print(b64PrivData);
  print('======&======');

  //print('privateKey: $privateKey.d');
  //print(privateKey.d!.bitLength);
  final signature2 = CryptoUtils.ecSignatureToBase64(sig);
  print('signature2: $signature2');

  //print('======&======');
}


bool testSignature(String pemPriv, String pemPub, Uint8List bytes) {
  final privateKey = CryptoUtils.ecPrivateKeyFromPem(pemPriv);
  final tmpPubKey = CryptoUtils.ecPublicKeyFromPem(pemPub);
  ECSignature sig =
      CryptoUtils.ecSign(privateKey, bytes, algorithmName: 'SHA-256/ECDSA');
  return CryptoUtils.ecVerify(tmpPubKey, bytes, sig, algorithm: 'SHA-256/ECDSA');
}

bool testSignature2(ECPrivateKey privateKey, String pemPub, Uint8List bytes) {
  final tmpPubKey = CryptoUtils.ecPublicKeyFromPem(pemPub);
  ECSignature sig =
      CryptoUtils.ecSign(privateKey, bytes, algorithmName: 'SHA-256/ECDSA');
  return CryptoUtils.ecVerify(tmpPubKey, bytes, sig, algorithm: 'SHA-256/ECDSA');
}

bool testSignature3(String comb, Uint8List bytes) {
  Iterable<String> l = LineSplitter.split(comb);
  String pemPriv = '';
  String pemPub = '';
  bool pub = false;

  l.forEach((e) {
      if (CryptoUtils.BEGIN_PUBLIC_KEY == e) {
        print('change');
        pub = true;
      }
      if (pub) {
        pemPub += e+'\n';
      } else {
        pemPriv += e+'\n';
      }
  });
  print('pemPriv: $pemPriv');
  print('pemPub: $pemPub');
  final privateKey = CryptoUtils.ecPrivateKeyFromPem(pemPriv);
  final tmpPubKey = CryptoUtils.ecPublicKeyFromPem(pemPub);
  ECSignature sig =
      CryptoUtils.ecSign(privateKey, bytes, algorithmName: 'SHA-256/ECDSA');
  return CryptoUtils.ecVerify(tmpPubKey, bytes, sig, algorithm: 'SHA-256/ECDSA');
}
